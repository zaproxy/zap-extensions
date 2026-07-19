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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

class LlmOptionsUnitTest extends TestUtils {

    private LlmOptions options;

    @BeforeAll
    static void setupAll() {
        mockMessages(new ExtensionLlm());
    }

    @BeforeEach
    void setup() {
        options = new LlmOptions();
        options.load(new ZapXmlConfiguration());
    }

    @Test
    void shouldNotBeConfiguredWhenNoProviderSet() {
        assertThat(options.isCommsConfigured(), is(false));
    }

    @Test
    void shouldNotBeConfiguredWhenProviderHasNoModels() {
        // Given
        options.setProviderConfigs(
                List.of(new LlmProviderConfig("claude", LlmProvider.CLAUDE, "key", "", List.of())));
        options.setDefaultProviderName("claude");

        // Then
        assertThat(options.isCommsConfigured(), is(false));
    }

    @Test
    void shouldBeConfiguredWhenProviderHasModel() {
        // Given
        options.setProviderConfigs(
                List.of(
                        new LlmProviderConfig(
                                "claude",
                                LlmProvider.CLAUDE,
                                "key",
                                "",
                                List.of("claude-sonnet-4-6"))));
        options.setDefaultProviderName("claude");

        // Then
        assertThat(options.isCommsConfigured(), is(true));
    }

    @Test
    void shouldNotBeConfiguredWhenEndpointRequiredProviderHasNoEndpoint() {
        // Given
        options.setProviderConfigs(
                List.of(
                        new LlmProviderConfig(
                                "ollama", LlmProvider.OLLAMA, "", "", List.of("llama3.2"))));
        options.setDefaultProviderName("ollama");

        // Then
        assertThat(options.isCommsConfigured(), is(false));
    }

    @Test
    void shouldReturnModelIssueWhenProviderHasNoModels() {
        // Given
        options.setProviderConfigs(
                List.of(new LlmProviderConfig("claude", LlmProvider.CLAUDE, "key", "", List.of())));
        options.setDefaultProviderName("claude");

        // When
        String issue = options.getCommsIssue();

        // Then
        assertThat(issue, notNullValue());
        assertThat(issue, containsString("model"));
    }

    @Test
    void shouldReturnNoIssueWhenProviderIsFullyConfigured() {
        // Given
        options.setProviderConfigs(
                List.of(
                        new LlmProviderConfig(
                                "claude",
                                LlmProvider.CLAUDE,
                                "key",
                                "",
                                List.of("claude-sonnet-4-6"))));
        options.setDefaultProviderName("claude");

        // Then
        assertThat(options.getCommsIssue(), nullValue());
    }
}
