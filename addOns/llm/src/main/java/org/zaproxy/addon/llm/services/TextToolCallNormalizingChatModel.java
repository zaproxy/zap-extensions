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

import dev.langchain4j.agent.tool.ToolExecutionRequest;
import dev.langchain4j.data.message.AiMessage;
import dev.langchain4j.data.message.UserMessage;
import dev.langchain4j.model.ModelProvider;
import dev.langchain4j.model.chat.ChatModel;
import dev.langchain4j.model.chat.ChatRequestOptions;
import dev.langchain4j.model.chat.listener.ChatModelListener;
import dev.langchain4j.model.chat.request.ChatRequest;
import dev.langchain4j.model.chat.request.ChatRequestParameters;
import dev.langchain4j.model.chat.response.ChatResponse;
import dev.langchain4j.service.tool.ToolProvider;
import dev.langchain4j.service.tool.ToolProviderRequest;
import java.util.List;
import java.util.Optional;
import java.util.function.Predicate;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Rewrites assistant text that is actually a tool-call JSON payload into a structured tool
 * execution request so AiServices can run the tool loop.
 */
final class TextToolCallNormalizingChatModel implements ChatModel {

    private static final Logger LOGGER =
            LogManager.getLogger(TextToolCallNormalizingChatModel.class);

    private final ChatModel delegate;
    private final Predicate<String> knownTool;

    TextToolCallNormalizingChatModel(ChatModel delegate, List<ToolProvider> toolProviders) {
        this.delegate = delegate;
        this.knownTool = name -> isKnownTool(name, toolProviders);
    }

    @Override
    public ChatResponse chat(ChatRequest chatRequest) {
        return normalize(delegate.chat(chatRequest));
    }

    @Override
    public ChatResponse chat(ChatRequest chatRequest, ChatRequestOptions options) {
        return normalize(delegate.chat(chatRequest, options));
    }

    @Override
    public ChatRequestParameters defaultRequestParameters() {
        return delegate.defaultRequestParameters();
    }

    @Override
    public List<ChatModelListener> listeners() {
        return List.of();
    }

    @Override
    public ModelProvider provider() {
        return delegate.provider();
    }

    private ChatResponse normalize(ChatResponse response) {
        AiMessage aiMessage = response.aiMessage();
        if (aiMessage == null || aiMessage.hasToolExecutionRequests()) {
            return response;
        }

        Optional<ToolExecutionRequest> toolCall = TextToolCallParser.tryParse(aiMessage.text());
        if (toolCall.isEmpty() || !knownTool.test(toolCall.get().name())) {
            return response;
        }

        LOGGER.debug(
                "Normalizing text tool call for '{}' into a structured tool execution request",
                toolCall.get().name());
        return response.toBuilder().aiMessage(AiMessage.from(toolCall.get())).build();
    }

    private static boolean isKnownTool(String name, List<ToolProvider> toolProviders) {
        ToolProviderRequest request = new ToolProviderRequest(null, UserMessage.from(""));
        for (ToolProvider provider : toolProviders) {
            boolean known =
                    provider.provideTools(request).aiServiceTools().stream()
                            .anyMatch(tool -> name.equals(tool.name()));
            if (known) {
                return true;
            }
        }
        return false;
    }
}
