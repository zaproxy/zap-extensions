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

import java.util.List;
import org.parosproxy.paros.Constant;

public enum LlmProvider {
    NONE("llm.provider.none"),
    OLLAMA("llm.provider.ollama", List.of(new SuggestedEndpoint("http://localhost:11434/", ""))),
    OPENAI_COMPATIBLE(
            "llm.provider.openai.compatible",
            List.of(
                    new SuggestedEndpoint(
                            "https://openrouter.ai/api/v1", "llm.endpoint.label.openrouter"),
                    new SuggestedEndpoint("https://api.openai.com/v1", "llm.endpoint.label.openai"),
                    new SuggestedEndpoint(
                            "http://localhost:1234/v1", "llm.endpoint.label.lmstudio"),
                    new SuggestedEndpoint(
                            "http://localhost:8080/v1", "llm.endpoint.label.llamacpp"))),
    AZURE_OPENAI("llm.provider.azure.openai"),
    GOOGLE_GEMINI("llm.provider.google.gemini"),
    CLAUDE("llm.provider.claude"),
    ;

    private final String messageKey;
    private final List<SuggestedEndpoint> suggestedEndpoints;

    LlmProvider(String messageKey) {
        this(messageKey, List.of());
    }

    LlmProvider(String messageKey, List<SuggestedEndpoint> suggestedEndpoints) {
        this.messageKey = messageKey;
        this.suggestedEndpoints = suggestedEndpoints;
    }

    @Override
    public String toString() {
        return Constant.messages.getString(messageKey);
    }

    public boolean supportsEndpoint() {
        return this != NONE && this != GOOGLE_GEMINI && this != CLAUDE;
    }

    public boolean isEndpointRequired() {
        return this == OLLAMA || this == AZURE_OPENAI || this == OPENAI_COMPATIBLE;
    }

    public boolean isModelRequired() {
        return this != NONE;
    }

    /**
     * Whether providers of this type should be treated as trusted by default. Non cloud based
     * providers default to trusted; cloud based providers default to untrusted.
     */
    public boolean isTrustedByDefault() {
        return this == OLLAMA;
    }

    /**
     * Known endpoint base URLs for this provider.
     *
     * @return suggested endpoints, possibly empty
     */
    public List<SuggestedEndpoint> getSuggestedEndpoints() {
        return suggestedEndpoints;
    }

    /**
     * A suggested endpoint base URL for an LLM provider, with an optional UI label.
     *
     * @param url the endpoint base URL
     * @param labelKey i18n key for the display label, may be blank
     */
    public record SuggestedEndpoint(String url, String labelKey) {

        @Override
        public String toString() {
            return url;
        }

        /**
         * Returns the URL with an optional label, e.g. {@code http://localhost:1234/v1 (LM
         * Studio)}.
         *
         * @return the label
         */
        public String getLabel() {
            if (labelKey.isEmpty()) {
                return url;
            }
            return Constant.messages.getString(
                    "llm.endpoint.display", url, Constant.messages.getString(labelKey));
        }
    }
}
