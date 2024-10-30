package org.zaproxy.addon.llm.services;

import com.azure.ai.openai.models.ChatCompletionsJsonResponseFormat;
import dev.langchain4j.memory.ChatMemory;
import dev.langchain4j.memory.chat.MessageWindowChatMemory;
import dev.langchain4j.model.chat.ChatLanguageModel;
import dev.langchain4j.model.azure.AzureOpenAiChatModel;
import dev.langchain4j.service.AiServices;
import org.apache.commons.httpclient.util.HttpURLConnection;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpSender;
import org.parosproxy.paros.core.scanner.Alert;
import org.zaproxy.addon.llm.communication.Confidence;
import org.zaproxy.addon.llm.communication.HttpRequest;
import org.zaproxy.addon.llm.communication.HttpRequestList;
import org.zaproxy.addon.llm.ui.settings.LlmOptionsParam;
import org.zaproxy.addon.llm.utils.HistoryPersister;
import org.zaproxy.addon.llm.utils.Requestor;
import org.zaproxy.zap.extension.alert.ExtensionAlert;


import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.stream.Collectors;

public class LlmCommunicationService {

    private LlmOptionsParam llmOptionsParam;

    private static final Logger LOGGER = LogManager.getLogger(LlmCommunicationService.class);
    private static final String AI_REVIEWD_TAG_KEY = "AI-Reviewed";
    private static final String AI_REVIEWD_TAG_VALUE = "1";

    public String endpoint;
    private String apiKey;
    private String modelName;

    private LlmAssistant llmAssistant;
    private LlmResponseHandler listener;
    Requestor requestor;

    static ChatLanguageModel model;
    ChatMemory chatMemory;

    public LlmCommunicationService(String modelName, String apiKey, String endpoint){
        listener = new LlmResponseHandler();
        chatMemory = MessageWindowChatMemory.withMaxMessages(10);
        model = AzureOpenAiChatModel.builder()
                .apiKey(apiKey)
                .deploymentName(modelName)
                .endpoint(endpoint)
                .temperature(0.3)
                .responseFormat(new ChatCompletionsJsonResponseFormat())
                .listeners(List.of(listener))
                .logRequestsAndResponses(true)
                .build();

        llmAssistant = AiServices.builder(LlmAssistant.class)
                .chatLanguageModel(model)
                .chatMemory(chatMemory)
                .build();
        requestor = new Requestor(HttpSender.MANUAL_REQUEST_INITIATOR, new HistoryPersister());

    }

    private Integer importHttpCalls(String swaggercontent) throws IOException {
        HttpRequestList listHttpRequest = llmAssistant.extractHttpRequests(swaggercontent);
        if (listHttpRequest == null) throw new RuntimeException("An issue occurred hy trying to get response from LLM" );
        requestor.run(listHttpRequest);
        return listHttpRequest.getRequests().size();
    }

    public Integer importSwaggerFromUrl(String urlString) {
        Integer endpoint_count = 0;
        try {
            URL url = new URL(urlString);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");

            // Check for successful response code or throw error
            if (connection.getResponseCode() != 200) {
                throw new RuntimeException("Failed : HTTP error code : " + connection.getResponseCode());
            }

            // Read the response
            BufferedReader br = new BufferedReader(new InputStreamReader((connection.getInputStream())));
            String openApiDefinition = br.lines().collect(Collectors.joining());

            // Use the existing importSwagger method
            endpoint_count = importHttpCalls(openApiDefinition);

            connection.disconnect();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return endpoint_count;
    }

    public Integer importSwaggerFromFile(String filePath) {
        Integer endpoint_count = 0;

        try {
            // Read the file content into a String
            String openApiDefinition = new String(Files.readAllBytes(Paths.get(filePath)));

            // Use the existing importSwagger method
            endpoint_count = importHttpCalls(openApiDefinition);

        } catch (Exception e) {
            e.printStackTrace();
        }
        return endpoint_count;
    }

    public void reviewAlert(Alert alert) {

        Alert updated_alert = alert;
        Alert original_alert = updated_alert.newInstance();

        if(! alert.getTags().containsKey(AI_REVIEWD_TAG_KEY)) {
            Confidence conf_llm;
            LOGGER.debug("Reviewing alert :" + alert.getName());
            LOGGER.debug("Confidence level from ZAP : " + alert.getConfidence());
            conf_llm = llmAssistant.review(alert.getDescription(), alert.getEvidence());
            LOGGER.debug("Confidence level from LLM : " + conf_llm.getLevel() + " | Explanation : " + conf_llm.getExplanation());
            updated_alert.setConfidence(conf_llm.getLevel());
            updated_alert.setOtherInfo("LLM Explanation : " + conf_llm.getExplanation() + "\n" + alert.getOtherInfo());
            Map<String, String> alertTags = alert.getTags();

            alertTags.putIfAbsent(AI_REVIEWD_TAG_KEY,AI_REVIEWD_TAG_VALUE);
            updated_alert.setTags(alertTags);

            try {
                getExtAlert().updateAlert(updated_alert);
                getExtAlert().updateAlertInTree(original_alert, updated_alert);
                if (alert.getHistoryRef() != null) {
                    alert.getHistoryRef().updateAlert(updated_alert);
                    if (alert.getHistoryRef().getSiteNode() != null) {
                        // Needed if the same alert was raised on another href for the same
                        // SiteNode
                        alert.getHistoryRef().getSiteNode().updateAlert(updated_alert);
                    }
                }
            } catch (Exception e) {
                LOGGER.error(e.getMessage(), e);
            }
        }else{
            LOGGER.debug("Skipping reviewed alert : " + alert.getName());
        }
    }

    private ExtensionAlert getExtAlert() {
        return Control.getSingleton().getExtensionLoader().getExtension(ExtensionAlert.class);
    }

}

