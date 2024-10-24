package org.zaproxy.addon.llm;

import com.azure.ai.openai.models.ChatCompletionsJsonResponseFormat;
import dev.langchain4j.memory.chat.MessageWindowChatMemory;
import dev.langchain4j.model.chat.ChatLanguageModel;
import dev.langchain4j.model.chat.StreamingChatLanguageModel;
import dev.langchain4j.model.azure.AzureOpenAiChatModel;
import dev.langchain4j.model.chat.ChatLanguageModel;
import dev.langchain4j.service.AiServices;
import org.apache.commons.httpclient.URIException;
import org.apache.commons.httpclient.util.HttpURLConnection;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.llm.HttpRequest;
import org.parosproxy.paros.core.scanner.Alert;
import org.zaproxy.zap.extension.alert.AlertNode;
import org.zaproxy.zap.extension.alert.ExtensionAlert;
import org.zaproxy.zap.extension.api.ApiException;

import javax.swing.tree.DefaultTreeModel;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class AnswerService {

    private LlmOptionsParam llmOptionsParam;

    private static final Logger LOGGER = LogManager.getLogger(AnswerService.class);
    public static String ENDPOINT = "https://ecorp.openai.azure.com/";

    private Assistant assistant;
    Requestor requestor;

    static ChatLanguageModel model;

    public void init(){
        initAgent();
    }

    private void initAgent(){

        this.llmOptionsParam = getOptionsParam();
        LOGGER.info("Getting API KEY : " + llmOptionsParam.getApiKey());

        model = AzureOpenAiChatModel.builder()
                .apiKey(llmOptionsParam.getApiKey())
                .deploymentName(llmOptionsParam.getModelName())
                .endpoint(ENDPOINT)
                .temperature(0.3)
                .responseFormat(new ChatCompletionsJsonResponseFormat())
                .logRequestsAndResponses(true)
                .build();
        assistant = AiServices.builder(Assistant.class)
                .chatLanguageModel(model)
                .build();
        requestor = new Requestor(HttpSender.MANUAL_REQUEST_INITIATOR, new HistoryPersister());
    }

    private void importHttpCalls(String swaggercontent) throws IOException {
        HttpRequestList listHttpRequest = assistant.extractHttpRequests(swaggercontent);
        requestor.run(listHttpRequest);
    }

    void importSwaggerFromUrl(String urlString) {
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
            importHttpCalls(openApiDefinition);

            connection.disconnect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    void importSwaggerFromFile(String filePath) {
        try {
            // Read the file content into a String
            String openApiDefinition = new String(Files.readAllBytes(Paths.get(filePath)));

            // Use the existing importSwagger method
            importHttpCalls(openApiDefinition);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    void reviewAlerts(Set<Alert> alerts) throws HttpMalformedHeaderException, DatabaseException {
        for (Alert alert : alerts) {
            reviewAlert(alert);
        }
    }

    void reviewAlert(Alert alert) throws HttpMalformedHeaderException, DatabaseException {
        // maybe filter by AI-Review tag ?
        if(! alert.getTags().containsKey("AI-Reviewed")) {
            Confidence conf_llm;
            LOGGER.info("##############Reviewing alert :" + alert.getName());
            LOGGER.info("\tConfidence level from ZAP :\t" + alert.getConfidence());
            conf_llm = assistant.review(alert.getDescription(), alert.getEvidence());
            // provide the input vector as well https://www.zaproxy.org/docs/desktop/ui/dialogs/options/ascaninput/
            LOGGER.info("\tConfidence level from LLM : " + conf_llm.getLevel() + " for the following reason : " + conf_llm.getExplanation());
            LOGGER.info("Updating the confidence score");
            alert.setConfidence(conf_llm.getLevel());
            alert.setOtherInfo("<b>LLM Explnation</b> : " + conf_llm.getExplanation() + "\n" + alert.getOtherInfo());
            Map<String, String> alertTags = alert.getTags();
            alertTags.putIfAbsent("AI-Reviewed", "1");
            alert.setTags(alertTags);
            Control.getSingleton().getExtensionLoader().getExtension(ExtensionAlert.class).updateAlert(alert);
        }else{
            LOGGER.info("Skipping reviewed alert : " + alert.getName());
        }
    }

    private List<Alert> getAlerts()
            throws SecurityException,
            IllegalArgumentException {
        ExtensionAlert extAlert = getExtAlert();

        return extAlert.getAllAlerts();
    }

    private ExtensionAlert getExtAlert() {
        return Control.getSingleton().getExtensionLoader().getExtension(ExtensionAlert.class);
    }

    private void processAlertUpdate(Alert updatedAlert) throws ApiException {
        try {
            ExtensionAlert extAlert = getExtAlert();
            extAlert.updateAlert(updatedAlert);
            extAlert.updateAlertInTree(updatedAlert, updatedAlert);

        } catch (HttpMalformedHeaderException | DatabaseException e) {
            LOGGER.error(e.getMessage(), e);
            throw new ApiException(ApiException.Type.INTERNAL_ERROR, e);
        }
    }

    public LlmOptionsParam getOptionsParam() {
        if (llmOptionsParam == null) {
            llmOptionsParam = new LlmOptionsParam();
        }
        return llmOptionsParam;
    }
}

