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

import org.apache.commons.lang3.StringUtils;
import org.parosproxy.paros.Constant;

public enum LlmProvider {
    NONE("llm.provider.none"),
    OLLAMA("llm.provider.ollama"),
    OPENROUTER("llm.provider.openrouter"),
    AZURE_OPENAI("llm.provider.azure.openai"),
    GOOGLE_GEMINI("llm.provider.google.gemini"),
    CLAUDE("llm.provider.claude"),
    JLAMA("llm.provider.jlama"),
    ;

    /** Directory under the ZAP home used for locally downloaded Jlama models. */
    public static final String LOCAL_MODELS_DIR = "llm-models";

    private final String messageKey;

    LlmProvider(String messageKey) {
        this.messageKey = messageKey;
    }

    @Override
    public String toString() {
        return Constant.messages.getString(messageKey);
    }

    public boolean supportsEndpoint() {
        return this != NONE && this != GOOGLE_GEMINI && this != CLAUDE && this != JLAMA;
    }

    public boolean supportsApiKey() {
        return this != NONE && this != OLLAMA && this != JLAMA;
    }

    public boolean isEndpointRequired() {
        return this == OLLAMA || this == AZURE_OPENAI;
    }

    public boolean isModelRequired() {
        return this != NONE;
    }

    /**
     * Whether providers of this type should be treated as trusted by default. Non cloud based
     * providers default to trusted; cloud based providers default to untrusted.
     */
    public boolean isTrustedByDefault() {
        return this == OLLAMA || this == JLAMA;
    }

    /**
     * Returns {@code true} when the "model" value is a local filesystem path rather than a remote
     * model name.
     */
    public boolean isLocalModelPath() {
        return this == JLAMA;
    }

    /**
     * Returns {@code true} when this provider is supplied by another add-on via {@link
     * LlmChatModelFactory}.
     */
    public boolean requiresExternalFactory() {
        return this == JLAMA;
    }

    /**
     * Returns a short UI label for a configured model. For local-path providers this is the
     * directory name only.
     *
     * @param model the configured model id or path
     * @return the display name
     */
    public String toDisplayModelName(String model) {
        if (!isLocalModelPath() || StringUtils.isBlank(model)) {
            return model;
        }
        return LocalLlmModelPath.toDisplayName(model);
    }

    public String getDefaultEndpoint() {
        if (this == OPENROUTER) {
            return "https://openrouter.ai/api/v1";
        }
        return "";
    }
}
