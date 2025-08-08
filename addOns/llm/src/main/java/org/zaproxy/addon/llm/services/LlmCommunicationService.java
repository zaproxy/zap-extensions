/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.addon.llm.services;

import com.azure.ai.openai.models.ChatCompletionsJsonResponseFormat;
import dev.langchain4j.memory.ChatMemory;
import dev.langchain4j.memory.chat.MessageWindowChatMemory;
import dev.langchain4j.model.azure.AzureOpenAiChatModel;
import dev.langchain4j.model.chat.ChatLanguageModel;
import dev.langchain4j.model.ollama.OllamaChatModel;
import dev.langchain4j.service.AiServices;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.apache.commons.httpclient.util.HttpURLConnection;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.llm.LlmOptions;
import org.zaproxy.addon.llm.communication.Confidence;
import org.zaproxy.addon.llm.communication.HttpRequestList;
import org.zaproxy.addon.llm.utils.HistoryPersister;
import org.zaproxy.addon.llm.utils.Requestor;
import org.zaproxy.zap.extension.alert.ExtensionAlert;
import org.zaproxy.zap.utils.Stats;

public class LlmCommunicationService {

    private static final Logger LOGGER = LogManager.getLogger(LlmCommunicationService.class);
    private static final String AI_REVIEWED_TAG_KEY = "AI-Reviewed";

    private LlmAssistant llmAssistant;
    private LlmResponseHandler listener;
    Requestor requestor;

    static ChatLanguageModel model;
    ChatMemory chatMemory;

    public LlmCommunicationService(LlmOptions options) {
        listener = new LlmResponseHandler();
        chatMemory = MessageWindowChatMemory.withMaxMessages(10);
        model = buildModel(options);

        llmAssistant =
                AiServices.builder(LlmAssistant.class)
                        .chatLanguageModel(model)
                        .chatMemory(chatMemory)
                        .build();
        requestor = new Requestor(HttpSender.MANUAL_REQUEST_INITIATOR, new HistoryPersister());
    }

    private ChatLanguageModel buildModel(LlmOptions options) {
        return switch (options.getModelProvider()) {
            case AZURE_OPENAI ->
                    AzureOpenAiChatModel.builder()
                            .apiKey(options.getApiKey())
                            .deploymentName(options.getModelName())
                            .endpoint(options.getEndpoint())
                            .temperature(0.3)
                            .responseFormat(new ChatCompletionsJsonResponseFormat())
                            .listeners(List.of(listener))
                            .logRequestsAndResponses(true)
                            .build();
            case OLLAMA ->
                    OllamaChatModel.builder()
                            .baseUrl(options.getEndpoint())
                            .modelName(options.getModelName())
                            .temperature(0.3)
                            .listeners(List.of(listener))
                            .logRequests(true)
                            .logResponses(true)
                            .build();
            default -> throw new RuntimeException("Unknown model provider");
        };
    }

    private Integer importHttpCalls(String openapiContent) throws IOException {
        Stats.incCounter("stats.llm.openapiseq.call");
        HttpRequestList listHttpRequest = llmAssistant.extractHttpRequests(openapiContent);
        if (listHttpRequest == null) {
            Stats.incCounter("stats.llm.openapiseq.fail");
            throw new RuntimeException(
                    "An issue occurred when trying to get response from the LLM");
        }
        Stats.incCounter("stats.llm.openapiseq.result.count", listHttpRequest.getRequests().size());
        requestor.run(listHttpRequest);
        return listHttpRequest.getRequests().size();
    }

    public Integer importOpenapiFromUrl(String urlString) {
        Integer endpointCount = 0;
        try {
            URL url = new URL(urlString);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");

            // Check for successful response code or throw error
            if (connection.getResponseCode() != 200) {
                throw new RuntimeException(
                        String.format(
                                "Failed : HTTP error code : %s ", connection.getResponseCode()));
            }

            // Read the response
            BufferedReader br =
                    new BufferedReader(new InputStreamReader((connection.getInputStream())));
            String openApiDefinition = br.lines().collect(Collectors.joining());

            // Use the existing importOpenapi method
            endpointCount = importHttpCalls(openApiDefinition);

            connection.disconnect();
        } catch (Exception e) {
            LOGGER.error(e.getMessage());
        }
        return endpointCount;
    }

    public Integer importOpenapiFromFile(String filePath) {
        Integer endpointCount = 0;

        try {
            // Read the file content into a String
            String openApiDefinition = new String(Files.readAllBytes(Paths.get(filePath)));

            // Use the existing importOpenapi method
            endpointCount = importHttpCalls(openApiDefinition);

        } catch (Exception e) {
            LOGGER.error(e.getMessage());
        }
        return endpointCount;
    }

    public void reviewAlert(Alert alert) {

        Alert updatedAlert = alert;
        Alert originalAlert = updatedAlert.newInstance();

        if (isPreviouslyReviewed(alert)) {
            LOGGER.debug("Skipping previously reviewed alert : {} ", alert.getName());
        } else {
            Confidence llmConfidence;
            LOGGER.debug("Reviewing alert : {}", alert.getName());
            LOGGER.debug("Confidence level from ZAP : {}", alert.getConfidence());
            Stats.incCounter("stats.llm.alertreview.call");
            if (StringUtils.isBlank(alert.getOtherInfo())) {
                llmConfidence = llmAssistant.review(alert.getDescription(), alert.getEvidence());
            } else {
                llmConfidence =
                        llmAssistant.review(
                                alert.getDescription(), alert.getEvidence(), alert.getOtherInfo());
            }

            if (llmConfidence.getLevel() == alert.getConfidence()) {
                Stats.incCounter("stats.llm.alertreview.result.same");
            } else {
                Stats.incCounter("stats.llm.alertreview.result.changed");
            }

            LOGGER.debug(
                    "Confidence level from LLM : {} | Explanation : {}",
                    llmConfidence.getLevel(),
                    llmConfidence.getExplanation());
            updatedAlert.setConfidence(llmConfidence.getLevel());
            updatedAlert.setOtherInfo(getUpdatedOtherInfo(alert, llmConfidence));
            Map<String, String> alertTags = alert.getTags();

            alertTags.putIfAbsent(AI_REVIEWED_TAG_KEY, "");
            updatedAlert.setTags(alertTags);

            try {
                getExtAlert().updateAlert(updatedAlert);
                getExtAlert().updateAlertInTree(originalAlert, updatedAlert);
                if (alert.getHistoryRef() != null) {
                    alert.getHistoryRef().updateAlert(updatedAlert);
                    if (alert.getHistoryRef().getSiteNode() != null) {
                        // Needed if the same alert was raised on another href for the same
                        // SiteNode
                        alert.getHistoryRef().getSiteNode().updateAlert(updatedAlert);
                    }
                }
            } catch (Exception e) {
                LOGGER.error(e.getMessage(), e);
            }
        }
    }

    private static boolean isPreviouslyReviewed(Alert alert) {
        return alert.getTags().containsKey(AI_REVIEWED_TAG_KEY);
    }

    private static String getUpdatedOtherInfo(Alert alert, Confidence llmConfidence) {
        return Constant.messages.getString(
                "llm.reviewalert.otherinfo", alert.getOtherInfo(), llmConfidence.getExplanation());
    }

    private static ExtensionAlert getExtAlert() {
        return Control.getSingleton().getExtensionLoader().getExtension(ExtensionAlert.class);
    }
}
