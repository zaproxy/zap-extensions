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
package org.zaproxy.addon.llm.ui;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

import org.junit.jupiter.api.Test;
import org.zaproxy.addon.llm.LlmProvider;

class LlmProviderEndpointPolicyUnitTest {

    @Test
    void shouldEnableEndpointAndApplyDefaultForOpenRouter() {
        // Given / When
        boolean enabled = LlmProviderEndpointPolicy.endpointEnabled(LlmProvider.OPENROUTER);
        String endpoint = LlmProviderEndpointPolicy.endpointValueOnSelect(LlmProvider.OPENROUTER);

        // Then
        assertThat(enabled, is(true));
        assertThat(endpoint, is("https://openrouter.ai/api/v1"));
    }

    @Test
    void shouldDisableEndpointAndClearValueForGoogleGemini() {
        // Given / When
        boolean enabled = LlmProviderEndpointPolicy.endpointEnabled(LlmProvider.GOOGLE_GEMINI);
        String endpoint =
                LlmProviderEndpointPolicy.endpointValueOnSelect(LlmProvider.GOOGLE_GEMINI);

        // Then
        assertThat(enabled, is(false));
        assertThat(endpoint, is(""));
    }

    @Test
    void shouldEnableEndpointAndClearValueForProvidersWithoutDefaultEndpoint() {
        assertThat(LlmProviderEndpointPolicy.endpointEnabled(LlmProvider.AZURE_OPENAI), is(true));
        assertThat(
                LlmProviderEndpointPolicy.endpointValueOnSelect(LlmProvider.AZURE_OPENAI), is(""));

        assertThat(LlmProviderEndpointPolicy.endpointEnabled(LlmProvider.OLLAMA), is(true));
        assertThat(LlmProviderEndpointPolicy.endpointValueOnSelect(LlmProvider.OLLAMA), is(""));
    }

    @Test
    void shouldDisableEndpointAndClearValueForNullProvider() {
        assertThat(LlmProviderEndpointPolicy.endpointEnabled(null), is(false));
        assertThat(LlmProviderEndpointPolicy.endpointValueOnSelect(null), is(""));
    }
}
