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
import dev.langchain4j.memory.ChatMemory;
import dev.langchain4j.memory.chat.MessageWindowChatMemory;
import dev.langchain4j.model.azure.AzureOpenAiChatModel;
import dev.langchain4j.model.chat.ChatModel;
import dev.langchain4j.model.chat.request.ChatRequest;
import dev.langchain4j.model.chat.request.ResponseFormat;
import dev.langchain4j.model.chat.response.ChatResponse;
import dev.langchain4j.model.googleai.GoogleAiGeminiChatModel;
import dev.langchain4j.model.openai.OpenAiChatModel;
import dev.langchain4j.model.ollama.OllamaChatModel;
import dev.langchain4j.service.AiServices;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.URI;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import lombok.Getter;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.httpclient.util.HttpURLConnection;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.llm.LlmProvider;
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

    private ChatModel model;
    private static final ObjectMapper objectMapper = new ObjectMapper();
    private static final ObjectWriter prettyWriter = objectMapper.writerWithDefaultPrettyPrinter();
    private ChatMemory chatMemory;
    private final HttpClient httpClient = HttpClient.newHttpClient();

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
            case OPENAI -> {
                String baseUrl = StringUtils.trimToEmpty(pconf.getEndpoint());
                if (baseUrl.isEmpty()) {
                    baseUrl = pconf.getProvider().getDefaultEndpoint();
                }
                yield OpenAiChatModel.builder()
                        .apiKey(pconf.getApiKey())
                        .baseUrl(baseUrl)
                        .modelName(modelName)
                        .temperature(0.3)
                        .listeners(List.of(listener))
                        .build();
            }
            case OPENROUTER -> {
                String baseUrl = StringUtils.trimToEmpty(pconf.getEndpoint());
                if (baseUrl.isEmpty()) {
                    baseUrl = pconf.getProvider().getDefaultEndpoint();
                }
                yield OpenAiChatModel.builder()
                        .apiKey(pconf.getApiKey())
                        .baseUrl(baseUrl)
                        .modelName(modelName)
                        .temperature(0.3)
                        .listeners(List.of(listener))
                        .build();
            }
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
        if (model == null) {
            throw new IllegalStateException("Chat model was not initialised.");
        }
        return model.chat(chatRequest);
    }

    public String chatText(ChatRequest chatRequest) {
        if (pconf != null && pconf.getProvider() == LlmProvider.OPENROUTER) {
            try {
                return openAiCompatibleChat(chatRequest);
            } catch (RuntimeException e) {
                throw e;
            } catch (Exception e) {
                throw new RuntimeException(e.getMessage(), e);
            }
        }
        try {
            return chat(chatRequest).aiMessage().text();
        } catch (RuntimeException e) {
            if (isOpenAiCompatible(pconf)) {
                try {
                    return openAiCompatibleChat(chatRequest);
                } catch (Exception fallbackError) {
                    e.addSuppressed(fallbackError);
                }
            }
            throw e;
        }
    }

    public String chat(String str) {
        if (model == null) {
            throw new IllegalStateException("Chat model was not initialised.");
        }
        return model.chat(str);
    }

    private static boolean isOpenAiCompatible(LlmProviderConfig config) {
        if (config == null) {
            return false;
        }
        LlmProvider provider = config.getProvider();
        return provider == LlmProvider.OPENAI || provider == LlmProvider.OPENROUTER;
    }

    private String openAiCompatibleChat(ChatRequest chatRequest) throws Exception {
        if (StringUtils.isBlank(modelName)) {
            throw new IllegalStateException("No model name configured.");
        }
        if (StringUtils.isBlank(pconf.getApiKey())) {
            throw new IllegalStateException("No API key configured.");
        }

        String baseUrl = StringUtils.trimToEmpty(pconf.getEndpoint());
        if (baseUrl.isEmpty()) {
            baseUrl = pconf.getProvider().getDefaultEndpoint();
        }
        if (StringUtils.isBlank(baseUrl)) {
            throw new IllegalStateException("No base URL configured for provider.");
        }

        URI uri = URI.create(trimTrailingSlash(baseUrl) + "/chat/completions");

        Map<String, Object> payload =
                Map.of(
                        "model",
                        modelName,
                        "temperature",
                        0.3,
                        "messages",
                        chatRequest.messages().stream()
                                .map(
                                        msg -> {
                                            String role;
                                            String content;
                                            if (msg instanceof dev.langchain4j.data.message.SystemMessage sm) {
                                                role = "system";
                                                content = sm.text();
                                            } else if (msg instanceof dev.langchain4j.data.message.UserMessage um) {
                                                role = "user";
                                                content =
                                                        um.hasSingleText()
                                                                ? um.singleText()
                                                                : um.contents().toString();
                                            } else if (msg instanceof dev.langchain4j.data.message.AiMessage am) {
                                                role = "assistant";
                                                content = am.text();
                                            } else {
                                                role = "user";
                                                content = msg.toString();
                                            }
                                            return Map.of("role", role, "content", content);
                                        })
                                .toList());

        String body = objectMapper.writeValueAsString(payload);

        HttpRequest request =
                HttpRequest.newBuilder()
                        .uri(uri)
                        .header("Authorization", "Bearer " + pconf.getApiKey())
                        .header("Content-Type", "application/json")
                        .header("Accept", "application/json")
                        .header("User-Agent", "ZAP-LLM-Addon")
                        .POST(HttpRequest.BodyPublishers.ofString(body))
                        .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new RuntimeException(
                    "LLM HTTP " + response.statusCode() + ": " + extractErrorMessage(response.body()));
        }

        return extractAssistantContent(response.body());
    }

    private static String extractAssistantContent(String responseBody) throws Exception {
        var root = objectMapper.readTree(StringUtils.defaultString(responseBody));
        var choices = root.path("choices");
        if (!choices.isArray() || choices.isEmpty()) {
            throw new RuntimeException("Unexpected LLM response (missing choices).");
        }
        var content = choices.get(0).path("message").path("content").asText(null);
        if (StringUtils.isBlank(content)) {
            throw new RuntimeException("Unexpected LLM response (missing message content).");
        }
        return content;
    }

    private static String extractErrorMessage(String responseBody) {
        try {
            var root = objectMapper.readTree(StringUtils.defaultString(responseBody));
            var msg = root.path("error").path("message").asText(null);
            if (StringUtils.isNotBlank(msg)) {
                return msg;
            }
        } catch (Exception ignore) {
            // ignored
        }
        String trimmed = StringUtils.trimToEmpty(responseBody);
        if (trimmed.isEmpty()) {
            return "Empty response body.";
        }
        return trimmed.length() > 500 ? trimmed.substring(0, 500) + "…" : trimmed;
    }

    private static String trimTrailingSlash(String url) {
        String trimmed = StringUtils.trimToEmpty(url);
        while (trimmed.endsWith("/")) {
            trimmed = trimmed.substring(0, trimmed.length() - 1);
        }
        return trimmed;
    }

    public static <T> T mapResponse(ChatResponse response, Class<T> clazz)
            throws JsonMappingException, JsonProcessingException {
        return objectMapper.readValue(response.aiMessage().text(), clazz);
    }

    public static String mapJsonObject(Map<String, Object> payload) throws JsonProcessingException {
        return prettyWriter.writeValueAsString(payload);
    }

    public void switchToOutputTab() {
        this.listener.setFocus();
    }

    public void setOutputEnabled(boolean enabled) {
        if (listener != null) {
            listener.setOutputEnabled(enabled);
        }
    }
}
