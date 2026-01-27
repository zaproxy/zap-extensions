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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.langchain4j.memory.ChatMemory;
import dev.langchain4j.memory.chat.MessageWindowChatMemory;
import dev.langchain4j.model.azure.AzureOpenAiChatModel;
import dev.langchain4j.model.chat.ChatModel;
import dev.langchain4j.model.chat.request.ChatRequest;
import dev.langchain4j.model.chat.request.ResponseFormat;
import dev.langchain4j.model.chat.response.ChatResponse;
import dev.langchain4j.model.googleai.GoogleAiGeminiChatModel;
import dev.langchain4j.model.ollama.OllamaChatModel;
import dev.langchain4j.service.AiServices;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;
import java.util.stream.Collectors;
import lombok.Getter;
import org.apache.commons.httpclient.util.HttpURLConnection;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.llm.LlmProviderConfig;
import org.zaproxy.addon.llm.communication.HttpRequestList;
import org.zaproxy.addon.llm.utils.HistoryPersister;
import org.zaproxy.addon.llm.utils.Requestor;
import org.zaproxy.zap.utils.Stats;

public class LlmCommunicationService {

    private static final Logger LOGGER = LogManager.getLogger(LlmCommunicationService.class);
    protected static final String AI_REVIEWED_TAG_KEY = "AI-Reviewed";

    private LlmAssistant llmAssistant;
    private LlmResponseHandler listener;
    @Getter private LlmProviderConfig pconf;
    @Getter private String modelName;
    private Requestor requestor;

    private static ChatModel model;
    private static ObjectMapper objectMapper = new ObjectMapper();
    private ChatMemory chatMemory;

    public LlmCommunicationService(
            LlmProviderConfig pconf, String modelName, String outputTabName) {
        this.pconf = pconf;
        this.modelName = modelName;
        listener = new LlmResponseHandler(outputTabName);
        chatMemory = MessageWindowChatMemory.withMaxMessages(10);
        model = buildModel();

        llmAssistant =
                AiServices.builder(LlmAssistant.class)
                        .chatModel(model)
                        .chatMemory(chatMemory)
                        .build();
        requestor = new Requestor(HttpSender.MANUAL_REQUEST_INITIATOR, new HistoryPersister());
    }

    /** For testing purposes only. */
    LlmCommunicationService(LlmAssistant assistant) {
        this.llmAssistant = assistant;
    }

    private ChatModel buildModel() {

        return switch (pconf.getProvider()) {
            case AZURE_OPENAI ->
                    AzureOpenAiChatModel.builder()
                            .apiKey(pconf.getApiKey())
                            .deploymentName(modelName)
                            .endpoint(pconf.getEndpoint())
                            .temperature(0.3)
                            .responseFormat(ResponseFormat.JSON)
                            .listeners(List.of(listener))
                            .logRequestsAndResponses(true)
                            .build();
            case OLLAMA ->
                    OllamaChatModel.builder()
                            .baseUrl(pconf.getEndpoint())
                            .modelName(modelName)
                            .temperature(0.3)
                            .listeners(List.of(listener))
                            .logRequests(true)
                            .logResponses(true)
                            .build();
            case GOOGLE_GEMINI ->
                    GoogleAiGeminiChatModel.builder()
                            .apiKey(pconf.getApiKey())
                            .modelName(modelName)
                            .temperature(0.3)
                            .listeners(List.of(listener))
                            .logRequests(true)
                            .logResponses(true)
                            .build();
            default -> throw new RuntimeException("Unknown model provider");
        };
    }

    private Integer importHttpCalls(String openapiContent) throws RuntimeException {
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

    public ChatResponse chat(ChatRequest chatRequest) {
        return model.chat(chatRequest);
    }

    public String chat(String str) {
        return model.chat(str);
    }

    public static <T> T mapResponse(ChatResponse response, Class<T> clazz)
            throws JsonMappingException, JsonProcessingException {
        return objectMapper.readValue(response.aiMessage().text(), clazz);
    }

    public void switchToOutputTab() {
        this.listener.setFocus();
    }
}
