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

import dev.langchain4j.model.chat.listener.ChatModelErrorContext;
import dev.langchain4j.model.chat.listener.ChatModelListener;
import dev.langchain4j.model.chat.listener.ChatModelResponseContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class LlmResponseHandler implements ChatModelListener {

    private static final Logger LOGGER = LogManager.getLogger(LlmResponseHandler.class);

    @Override
    public void onResponse(ChatModelResponseContext responseContext) {
        LOGGER.info("Token usage = {} ", responseContext.chatResponse().tokenUsage());
    }

    @Override
    public void onError(ChatModelErrorContext errorContext) {
        LOGGER.error("LLM Error : {} ", errorContext.error().getMessage());
        throw new RuntimeException(
                String.format("LLM Error : %s", errorContext.error().getMessage()));
    }
}
