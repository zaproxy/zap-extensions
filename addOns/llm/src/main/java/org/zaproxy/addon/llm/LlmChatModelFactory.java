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
package org.zaproxy.addon.llm;

import dev.langchain4j.model.chat.ChatModel;
import dev.langchain4j.model.chat.listener.ChatModelListener;

/**
 * Creates a LangChain4j {@link ChatModel} for an {@link LlmProvider} that is implemented outside
 * the core LLM add-on (for example Jlama).
 */
public interface LlmChatModelFactory {

    /**
     * Returns the provider this factory handles.
     *
     * @return the provider
     */
    LlmProvider getProvider();

    /**
     * Creates a chat model for the given configuration.
     *
     * @param config the provider configuration
     * @param modelName the selected model name or local path
     * @param listener optional listener for requests/responses, may be {@code null}
     * @param withJsonResponseFormat whether JSON response format was requested (may be ignored if
     *     unsupported)
     * @return the chat model
     */
    ChatModel create(
            LlmProviderConfig config,
            String modelName,
            ChatModelListener listener,
            boolean withJsonResponseFormat);
}
