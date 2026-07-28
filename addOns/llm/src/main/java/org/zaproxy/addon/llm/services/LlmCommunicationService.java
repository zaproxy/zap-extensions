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
import com.fasterxml.jackson.databind.ObjectWriter;
import dev.langchain4j.data.message.SystemMessage;
import dev.langchain4j.memory.ChatMemory;
import dev.langchain4j.memory.chat.MessageWindowChatMemory;
import dev.langchain4j.model.anthropic.AnthropicChatModel;
import dev.langchain4j.model.azure.AzureOpenAiChatModel;
import dev.langchain4j.model.chat.ChatModel;
import dev.langchain4j.model.chat.listener.ChatModelListener;
import dev.langchain4j.model.chat.request.ChatRequest;
import dev.langchain4j.model.chat.request.ResponseFormat;
import dev.langchain4j.model.chat.response.ChatResponse;
import dev.langchain4j.model.googleai.GoogleAiGeminiChatModel;
import dev.langchain4j.model.ollama.OllamaChatModel;
import dev.langchain4j.model.openai.OpenAiChatModel;
import dev.langchain4j.service.AiServices;
import dev.langchain4j.service.UserMessage;
import dev.langchain4j.service.tool.ToolProvider;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import lombok.Getter;
import org.apache.commons.httpclient.util.HttpURLConnection;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.llm.ExtensionLlm;
import org.zaproxy.addon.llm.LlmChatModelFactory;
import org.zaproxy.addon.llm.LlmProvider;
import org.zaproxy.addon.llm.LlmProviderConfig;
import org.zaproxy.addon.llm.communication.HttpRequestList;
import org.zaproxy.addon.llm.utils.HistoryPersister;
import org.zaproxy.addon.llm.utils.Requestor;
import org.zaproxy.zap.utils.Stats;

public class LlmCommunicationService {

    private static final Logger LOGGER = LogManager.getLogger(LlmCommunicationService.class);
    protected static final String AI_REVIEWED_TAG_KEY = "AI-Reviewed";

    /**
     * System guidance included in every conversation so the model knows it is running inside ZAP.
     */
    static final String ZAP_INTEGRATION_SYSTEM_MESSAGE =
            """
            You are an assistant integrated into ZAP (Zed Attack Proxy), a tool for finding
            vulnerabilities in web applications. Help the user with web application
            security testing, ZAP usage, and related tasks. When tools are available,
            you may use them to interact with ZAP.
            """;

    private LlmAssistant llmAssistant;
    private LlmChatAssistant chatAssistant;
    private ChatModelListener listener;
    private LlmToolExecutionHandler toolExecutionHandler;
    @Getter private LlmProviderConfig pconf;
    @Getter private String modelName;
    @Getter private List<ToolProvider> toolProviders;
    private Requestor requestor;

    private ChatModel model;
    private static ObjectMapper objectMapper = new ObjectMapper();
    private static ObjectWriter prettyWriter = objectMapper.writerWithDefaultPrettyPrinter();
    private ChatMemory chatMemory;

    public LlmCommunicationService(
            LlmProviderConfig pconf,
            String modelName,
            ChatModelListener listener,
            List<ToolProvider> toolProviders,
            LlmToolExecutionHandler toolExecutionHandler) {
        this.pconf = pconf;
        this.modelName = modelName;
        this.listener = listener;
        this.toolExecutionHandler = toolExecutionHandler;
        this.toolProviders = toolProviders != null ? List.copyOf(toolProviders) : List.of();
        chatMemory = MessageWindowChatMemory.withMaxMessages(10);
        chatMemory.add(SystemMessage.from(ZAP_INTEGRATION_SYSTEM_MESSAGE));
        initialiseAssistants();
        requestor = new Requestor(HttpSender.MANUAL_REQUEST_INITIATOR, new HistoryPersister());
    }

    /**
     * Updates connection settings that should not reset conversation identity (for example
     * timeout). Rebuilds the underlying models when needed while keeping chat memory.
     */
    public void applyConnectionSettings(LlmProviderConfig updatedConfig) {
        if (updatedConfig == null) {
            return;
        }
        boolean timeoutChanged = pconf.getTimeoutSeconds() != updatedConfig.getTimeoutSeconds();
        this.pconf = updatedConfig;
        if (timeoutChanged) {
            initialiseAssistants();
        }
    }

    private void initialiseAssistants() {
        model = buildModel(true);

        llmAssistant =
                AiServices.builder(LlmAssistant.class)
                        .chatModel(model)
                        .chatMemory(chatMemory)
                        .build();

        var chatAssistantBuilder =
                AiServices.builder(LlmChatAssistant.class)
                        .chatModel(
                                pconf.getProvider() == LlmProvider.AZURE_OPENAI
                                        ? buildModel(false)
                                        : model)
                        .chatMemory(chatMemory)
                        .toolProviders(this.toolProviders);
        if (!this.toolProviders.isEmpty() && pconf.getProvider() == LlmProvider.JLAMA) {
            // Local models only see tools via the chat template; a short system hint helps smaller
            // Instruct models actually invoke them instead of answering in plain text.
            chatAssistantBuilder.systemMessage(
                    Constant.messages.getString("llm.chat.system.jlama.tools"));
        }
        if (toolExecutionHandler != null) {
            chatAssistantBuilder
                    .beforeToolExecution(toolExecutionHandler::beforeToolExecution)
                    .afterToolExecution(toolExecutionHandler::afterToolExecution);
        }
        chatAssistant = chatAssistantBuilder.build();
    }

    /** For testing purposes only. */
    LlmCommunicationService(LlmAssistant assistant) {
        this.llmAssistant = assistant;
    }

    /** For testing purposes only. */
    LlmCommunicationService(ChatModel model, ChatMemory chatMemory) {
        this.model = model;
        this.chatMemory = chatMemory;
    }

    /** For testing purposes only. */
    LlmCommunicationService(
            LlmProviderConfig pconf, String modelName, ChatModel model, ChatMemory chatMemory) {
        this.pconf = pconf;
        this.modelName = modelName;
        this.model = model;
        this.chatMemory = chatMemory;
        this.toolProviders = List.of();
    }

    /** For testing purposes only. */
    ChatMemory getChatMemory() {
        return chatMemory;
    }

    private ChatModel buildModel(boolean withJsonResponseFormat) {
        Duration timeout = Duration.ofSeconds(pconf.getTimeoutSeconds());

        return switch (pconf.getProvider()) {
            case AZURE_OPENAI -> {
                var builder =
                        AzureOpenAiChatModel.builder()
                                .apiKey(pconf.getApiKey())
                                .deploymentName(modelName)
                                .endpoint(pconf.getEndpoint())
                                .timeout(timeout)
                                .temperature(0.3)
                                .listeners(listener != null ? List.of(listener) : List.of())
                                .logRequestsAndResponses(true);
                if (withJsonResponseFormat) {
                    builder = builder.responseFormat(ResponseFormat.JSON);
                }
                yield builder.build();
            }
            case OLLAMA ->
                    OllamaChatModel.builder()
                            .baseUrl(pconf.getEndpoint())
                            .modelName(modelName)
                            .timeout(timeout)
                            .temperature(0.3)
                            .listeners(listener != null ? List.of(listener) : List.of())
                            .logRequests(true)
                            .logResponses(true)
                            .build();
            case OPENAI_COMPATIBLE ->
                    OpenAiChatModel.builder()
                            .apiKey(StringUtils.trimToNull(pconf.getApiKey()))
                            .baseUrl(pconf.getEndpoint())
                            .modelName(modelName)
                            .timeout(timeout)
                            .temperature(0.3)
                            .listeners(listener == null ? List.of() : List.of(listener))
                            .build();
            case GOOGLE_GEMINI ->
                    GoogleAiGeminiChatModel.builder()
                            .apiKey(pconf.getApiKey())
                            .modelName(modelName)
                            .timeout(timeout)
                            .temperature(0.3)
                            .listeners(listener != null ? List.of(listener) : List.of())
                            .logRequests(true)
                            .logResponses(true)
                            .build();
            case CLAUDE ->
                    AnthropicChatModel.builder()
                            .apiKey(pconf.getApiKey())
                            .modelName(modelName)
                            .timeout(timeout)
                            .temperature(0.3)
                            .listeners(listener != null ? List.of(listener) : List.of())
                            .logRequests(true)
                            .logResponses(true)
                            .build();
            case JLAMA -> createExternalModel(withJsonResponseFormat);
            default -> throw new RuntimeException("Unknown model provider");
        };
    }

    private ChatModel createExternalModel(boolean withJsonResponseFormat) {
        ExtensionLlm extensionLlm =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionLlm.class);
        LlmChatModelFactory factory =
                extensionLlm != null ? extensionLlm.getChatModelFactory(pconf.getProvider()) : null;
        if (factory == null) {
            throw new RuntimeException(
                    Constant.messages.getString(
                            "llm.error.factory.unavailable", pconf.getProvider().toString()));
        }
        return factory.create(pconf, modelName, listener, withJsonResponseFormat);
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
            URL url = URI.create(urlString).toURL();
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
        chatMemory.add(chatRequest.messages());
        ChatResponse response =
                model.chat(
                        ChatRequest.builder()
                                .messages(chatMemory.messages())
                                .parameters(chatRequest.parameters())
                                .build());
        chatMemory.add(response.aiMessage());
        return response;
    }

    public String chat(String str) {
        LOGGER.debug(
                "Sending chat message with {} prior memory message(s)",
                chatMemory.messages().size());
        return chatAssistant.chat(str);
    }

    public static <T> T mapResponse(ChatResponse response, Class<T> clazz)
            throws JsonMappingException, JsonProcessingException {
        return objectMapper.readValue(response.aiMessage().text(), clazz);
    }

    public static String mapJsonObject(Map<String, Object> payload) throws JsonProcessingException {
        return prettyWriter.writeValueAsString(payload);
    }

    interface LlmChatAssistant {
        String chat(@UserMessage String message);
    }
}
