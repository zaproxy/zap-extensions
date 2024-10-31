/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.llm.communication.Confidence;
import org.zaproxy.addon.llm.communication.HttpRequestList;
import org.zaproxy.addon.llm.ui.settings.LlmOptionsParam;
import org.zaproxy.addon.llm.utils.HistoryPersister;
import org.zaproxy.addon.llm.utils.Requestor;
import org.zaproxy.zap.extension.alert.ExtensionAlert;

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

    public LlmCommunicationService(String modelName, String apiKey, String endpoint) {
        listener = new LlmResponseHandler();
        chatMemory = MessageWindowChatMemory.withMaxMessages(10);
        model =
                AzureOpenAiChatModel.builder()
                        .apiKey(apiKey)
                        .deploymentName(modelName)
                        .endpoint(endpoint)
                        .temperature(0.3)
                        .responseFormat(new ChatCompletionsJsonResponseFormat())
                        .listeners(List.of(listener))
                        .logRequestsAndResponses(true)
                        .build();

        llmAssistant =
                AiServices.builder(LlmAssistant.class)
                        .chatLanguageModel(model)
                        .chatMemory(chatMemory)
                        .build();
        requestor = new Requestor(HttpSender.MANUAL_REQUEST_INITIATOR, new HistoryPersister());
    }

    private Integer importHttpCalls(String swaggercontent) throws IOException {
        HttpRequestList listHttpRequest = llmAssistant.extractHttpRequests(swaggercontent);
        if (listHttpRequest == null)
            throw new RuntimeException("An issue occurred hy trying to get response from LLM");
        requestor.run(listHttpRequest);
        return listHttpRequest.getRequests().size();
    }

    public Integer importSwaggerFromUrl(String urlString) {
        Integer endpointCount = 0;
        try {
            URL url = new URL(urlString);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");

            // Check for successful response code or throw error
            if (connection.getResponseCode() != 200) {
                throw new RuntimeException(
                        "Failed : HTTP error code : " + connection.getResponseCode());
            }

            // Read the response
            BufferedReader br =
                    new BufferedReader(new InputStreamReader((connection.getInputStream())));
            String openApiDefinition = br.lines().collect(Collectors.joining());

            // Use the existing importSwagger method
            endpointCount = importHttpCalls(openApiDefinition);

            connection.disconnect();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return endpointCount;
    }

    public Integer importSwaggerFromFile(String filePath) {
        Integer endpointCount = 0;

        try {
            // Read the file content into a String
            String openApiDefinition = new String(Files.readAllBytes(Paths.get(filePath)));

            // Use the existing importSwagger method
            endpointCount = importHttpCalls(openApiDefinition);

        } catch (Exception e) {
            LOGGER.error(e.getMessage());
        }
        return endpointCount;
    }

    public void reviewAlert(Alert alert) {

        Alert updatedAlert = alert;
        Alert originalAlert = updatedAlert.newInstance();

        if (!alert.getTags().containsKey(AI_REVIEWD_TAG_KEY)) {
            Confidence conf_llm;
            LOGGER.debug("Reviewing alert :" + alert.getName());
            LOGGER.debug("Confidence level from ZAP : " + alert.getConfidence());
            conf_llm = llmAssistant.review(alert.getDescription(), alert.getEvidence());
            LOGGER.debug(
                    "Confidence level from LLM : "
                            + conf_llm.getLevel()
                            + " | Explanation : "
                            + conf_llm.getExplanation());
            updatedAlert.setConfidence(conf_llm.getLevel());
            updatedAlert.setOtherInfo(
                    "LLM Explanation : " + conf_llm.getExplanation() + "\n" + alert.getOtherInfo());
            Map<String, String> alertTags = alert.getTags();

            alertTags.putIfAbsent(AI_REVIEWD_TAG_KEY, AI_REVIEWD_TAG_VALUE);
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
        } else {
            LOGGER.debug("Skipping reviewed alert : " + alert.getName());
        }
    }

    private ExtensionAlert getExtAlert() {
        return Control.getSingleton().getExtensionLoader().getExtension(ExtensionAlert.class);
    }
}
