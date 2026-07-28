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
package org.zaproxy.addon.llmlocal;

import dev.langchain4j.agent.tool.ToolSpecification;
import dev.langchain4j.model.ModelProvider;
import dev.langchain4j.model.chat.Capability;
import dev.langchain4j.model.chat.ChatModel;
import dev.langchain4j.model.chat.listener.ChatModelListener;
import dev.langchain4j.model.chat.request.ChatRequest;
import dev.langchain4j.model.chat.request.ChatRequestParameters;
import dev.langchain4j.model.chat.request.DefaultChatRequestParameters;
import dev.langchain4j.model.chat.response.ChatResponse;
import java.util.List;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Runs Jlama chat calls with the add-on classloader as the thread context classloader.
 *
 * <p>Jlama renders HuggingFace chat templates via Jinjava. Without the add-on classloader, Jinjava
 * can fail to load its EL classes (or render a broken prompt), so the model never sees the user
 * messages / tool instructions.
 *
 * <p>Also works around a Jlama bug where mentioning a registered tool name in prose (for example
 * when listing available tools) is treated as a tool call, JSON parsing yields {@code ToolCall}s
 * with a null name, and sorting those throws {@link NullPointerException}.
 */
final class JlamaClassLoaderAwareChatModel implements ChatModel {

    private static final Logger LOGGER = LogManager.getLogger(JlamaClassLoaderAwareChatModel.class);

    private final ChatModel delegate;

    JlamaClassLoaderAwareChatModel(ChatModel delegate) {
        this.delegate = delegate;
    }

    @Override
    public ChatResponse doChat(ChatRequest chatRequest) {
        List<ToolSpecification> tools = chatRequest.parameters().toolSpecifications();
        boolean hasTools = tools != null && !tools.isEmpty();
        if (hasTools) {
            LOGGER.debug(
                    "Jlama chat request includes {} tool specification(s); first={}",
                    tools.size(),
                    tools.get(0).name());
        } else {
            LOGGER.debug("Jlama chat request includes no tool specifications");
        }

        try {
            return chatWithAddOnClassLoader(chatRequest);
        } catch (RuntimeException e) {
            if (!hasTools || !isToolCallNameSortFailure(e)) {
                throw e;
            }
            LOGGER.warn(
                    "Jlama failed while parsing tool calls from the model response (often when "
                            + "tool names appear in prose). Retrying the same messages without tools: {}",
                    e.toString());
            LOGGER.debug("Jlama tool-call parse failure details", e);
            return chatWithAddOnClassLoader(withoutTools(chatRequest));
        }
    }

    private ChatResponse chatWithAddOnClassLoader(ChatRequest chatRequest) {
        // Delegate via chat() so JlamaChatModel's override (not the default doChat) is used.
        return JlamaRuntime.withAddOnClassLoader(() -> delegate.chat(chatRequest));
    }

    private static ChatRequest withoutTools(ChatRequest chatRequest) {
        // langchain4j treats an empty toolSpecifications list as "unset" in overrideWith, so we
        // must build a fresh parameters object that never had tools rather than clearing them.
        ChatRequestParameters original = chatRequest.parameters();
        ChatRequestParameters noTools =
                DefaultChatRequestParameters.builder()
                        .modelName(original.modelName())
                        .temperature(original.temperature())
                        .topP(original.topP())
                        .topK(original.topK())
                        .frequencyPenalty(original.frequencyPenalty())
                        .presencePenalty(original.presencePenalty())
                        .maxOutputTokens(original.maxOutputTokens())
                        .stopSequences(original.stopSequences())
                        .toolChoice(original.toolChoice())
                        .responseFormat(original.responseFormat())
                        .build();
        return ChatRequest.builder()
                .messages(chatRequest.messages())
                .parameters(noTools)
                .build();
    }

    /**
     * Jlama {@code AbstractModel.postProcessResponse} sorts parsed tool calls by name; a null name
     * produces this NPE (often wrapped by langchain4j's exception mapper).
     */
    static boolean isToolCallNameSortFailure(Throwable throwable) {
        for (Throwable current = throwable; current != null; current = current.getCause()) {
            if (current instanceof NullPointerException) {
                String message = current.getMessage();
                if (message != null
                        && message.contains("Comparable.compareTo")
                        && message.contains("Function.apply")) {
                    return true;
                }
            }
        }
        return false;
    }

    @Override
    public ChatRequestParameters defaultRequestParameters() {
        return delegate.defaultRequestParameters();
    }

    @Override
    public List<ChatModelListener> listeners() {
        return delegate.listeners();
    }

    @Override
    public ModelProvider provider() {
        return delegate.provider();
    }

    @Override
    public Set<Capability> supportedCapabilities() {
        return delegate.supportedCapabilities();
    }
}
