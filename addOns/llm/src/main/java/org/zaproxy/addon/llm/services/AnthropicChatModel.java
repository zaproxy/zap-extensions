/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.langchain4j.data.message.AiMessage;
import dev.langchain4j.data.message.SystemMessage;
import dev.langchain4j.data.message.UserMessage;
import dev.langchain4j.model.ModelProvider;
import dev.langchain4j.model.chat.ChatModel;
import dev.langchain4j.model.chat.listener.ChatModelListener;
import dev.langchain4j.model.chat.request.ChatRequest;
import dev.langchain4j.model.chat.response.ChatResponse;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.apache.commons.lang3.StringUtils;

/**
 * Minimal Anthropic (Claude) chat model implementation, allowing ZAP to use Claude without adding
 * additional LangChain4j modules.
 *
 * <p>Uses the Anthropic Messages API: POST {baseUrl}/messages.
 */
public class AnthropicChatModel implements ChatModel {

    private static final String ANTHROPIC_VERSION = "2023-06-01";
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private final HttpClient httpClient;
    private final String apiKey;
    private final String baseUrl;
    private final String modelName;
    private final double temperature;
    private final int maxTokens;
    private final List<ChatModelListener> listeners;

    private AnthropicChatModel(Builder builder) {
        this.httpClient =
                builder.httpClient != null ? builder.httpClient : HttpClient.newHttpClient();
        this.apiKey = StringUtils.trimToEmpty(builder.apiKey);
        this.baseUrl = StringUtils.trimToEmpty(builder.baseUrl);
        this.modelName = StringUtils.trimToEmpty(builder.modelName);
        this.temperature = builder.temperature;
        this.maxTokens = builder.maxTokens;
        this.listeners = builder.listeners != null ? List.copyOf(builder.listeners) : List.of();
    }

    public static Builder builder() {
        return new Builder();
    }

    @Override
    public List<ChatModelListener> listeners() {
        return listeners;
    }

    @Override
    public ModelProvider provider() {
        return ModelProvider.OTHER;
    }

    @Override
    public ChatResponse doChat(ChatRequest chatRequest) {
        if (StringUtils.isBlank(modelName)) {
            throw new IllegalStateException("No model name configured.");
        }
        if (StringUtils.isBlank(apiKey)) {
            throw new IllegalStateException("No API key configured.");
        }
        if (StringUtils.isBlank(baseUrl)) {
            throw new IllegalStateException("No base URL configured for provider.");
        }

        URI uri = URI.create(trimTrailingSlash(baseUrl) + "/messages");

        List<String> systemParts = new ArrayList<>();
        List<Map<String, Object>> messages = new ArrayList<>();

        for (var msg : chatRequest.messages()) {
            if (msg instanceof SystemMessage sm) {
                String text = StringUtils.trimToEmpty(sm.text());
                if (!text.isEmpty()) {
                    systemParts.add(text);
                }
                continue;
            }

            String role;
            String contentText;
            if (msg instanceof UserMessage um) {
                role = "user";
                contentText = um.hasSingleText() ? um.singleText() : String.valueOf(um.contents());
            } else if (msg instanceof AiMessage am) {
                role = "assistant";
                contentText = StringUtils.defaultIfBlank(am.text(), am.toString());
            } else {
                role = "user";
                contentText = msg.toString();
            }

            messages.add(
                    Map.of(
                            "role",
                            role,
                            "content",
                            List.of(Map.of("type", "text", "text", contentText))));
        }

        if (messages.isEmpty()) {
            messages.add(
                    Map.of("role", "user", "content", List.of(Map.of("type", "text", "text", ""))));
        }

        Map<String, Object> payload =
                systemParts.isEmpty()
                        ? Map.of(
                                "model",
                                modelName,
                                "temperature",
                                temperature,
                                "max_tokens",
                                maxTokens,
                                "messages",
                                messages)
                        : Map.of(
                                "model",
                                modelName,
                                "temperature",
                                temperature,
                                "max_tokens",
                                maxTokens,
                                "system",
                                String.join("\n\n", systemParts),
                                "messages",
                                messages);

        String body;
        try {
            body = OBJECT_MAPPER.writeValueAsString(payload);
        } catch (Exception e) {
            throw new RuntimeException("Failed to serialise Anthropic request payload.", e);
        }

        HttpRequest request =
                HttpRequest.newBuilder()
                        .uri(uri)
                        .header("x-api-key", apiKey)
                        .header("anthropic-version", ANTHROPIC_VERSION)
                        .header("Content-Type", "application/json")
                        .header("Accept", "application/json")
                        .header("User-Agent", "ZAP-LLM-Addon")
                        .POST(HttpRequest.BodyPublishers.ofString(body))
                        .build();

        try {
            HttpResponse<String> response =
                    httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() < 200 || response.statusCode() >= 300) {
                throw new RuntimeException(
                        "LLM HTTP "
                                + response.statusCode()
                                + ": "
                                + extractErrorMessage(response.body()));
            }
            String content = extractAssistantContent(response.body());
            return ChatResponse.builder()
                    .aiMessage(AiMessage.from(content))
                    .modelName(modelName)
                    .build();
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    private static String extractAssistantContent(String responseBody) throws Exception {
        JsonNode root = OBJECT_MAPPER.readTree(StringUtils.defaultString(responseBody));
        JsonNode content = root.path("content");
        if (!content.isArray() || content.isEmpty()) {
            throw new RuntimeException("Unexpected LLM response (missing content).");
        }
        StringBuilder sb = new StringBuilder();
        for (JsonNode block : content) {
            if ("text".equals(block.path("type").asText())) {
                String text = block.path("text").asText("");
                if (!text.isEmpty()) {
                    if (sb.length() != 0) {
                        sb.append("\n");
                    }
                    sb.append(text);
                }
            }
        }
        String result = sb.toString();
        if (StringUtils.isBlank(result)) {
            throw new RuntimeException("Unexpected LLM response (missing text content).");
        }
        return result;
    }

    private static String extractErrorMessage(String responseBody) {
        try {
            JsonNode root = OBJECT_MAPPER.readTree(StringUtils.defaultString(responseBody));
            String msg = root.path("error").path("message").asText(null);
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

    public static class Builder {
        private HttpClient httpClient;
        private String apiKey;
        private String baseUrl;
        private String modelName;
        private double temperature = 0.3;
        private int maxTokens = 1024;
        private List<ChatModelListener> listeners;

        public Builder httpClient(HttpClient httpClient) {
            this.httpClient = httpClient;
            return this;
        }

        public Builder apiKey(String apiKey) {
            this.apiKey = apiKey;
            return this;
        }

        public Builder baseUrl(String baseUrl) {
            this.baseUrl = baseUrl;
            return this;
        }

        public Builder modelName(String modelName) {
            this.modelName = modelName;
            return this;
        }

        public Builder temperature(double temperature) {
            this.temperature = temperature;
            return this;
        }

        public Builder maxTokens(int maxTokens) {
            this.maxTokens = maxTokens;
            return this;
        }

        public Builder listeners(List<ChatModelListener> listeners) {
            this.listeners = listeners;
            return this;
        }

        public AnthropicChatModel build() {
            return new AnthropicChatModel(this);
        }
    }
}
