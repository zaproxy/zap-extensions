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
package org.zaproxy.addon.llm;

import org.parosproxy.paros.Constant;

public enum LlmProvider {
    NONE("llm.provider.none"),
    OLLAMA("llm.provider.ollama"),
    AZURE_OPENAI("llm.provider.azure.openai"),
    GOOGLE_GEMINI("llm.provider.google.gemini"),
    ;

    private final String messageKey;

    LlmProvider(String messageKey) {
        this.messageKey = messageKey;
    }

    @Override
    public String toString() {
        return Constant.messages.getString(messageKey);
    }

    public boolean supportsEndpoint() {
        return this != NONE && this != GOOGLE_GEMINI;
    }
}
