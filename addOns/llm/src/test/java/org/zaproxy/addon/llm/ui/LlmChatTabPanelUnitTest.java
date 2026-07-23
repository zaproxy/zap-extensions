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

import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.zaproxy.addon.llm.ExtensionLlm;
import org.zaproxy.addon.llm.LlmProvider;
import org.zaproxy.addon.llm.LlmProviderConfig;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit test for {@link LlmChatTabPanel}. */
class LlmChatTabPanelUnitTest extends TestUtils {

    @BeforeAll
    static void beforeAll() {
        mockMessages(new ExtensionLlm());
    }

    @Test
    void shouldTreatConfigsAsSameCommsWhenOnlyModelsListDiffers() {
        // Given
        LlmProviderConfig before =
                new LlmProviderConfig(
                        "ollama", LlmProvider.OLLAMA, null, "http://localhost", List.of("m1"));
        LlmProviderConfig after =
                new LlmProviderConfig(
                        "ollama",
                        LlmProvider.OLLAMA,
                        null,
                        "http://localhost",
                        List.of("m1", "m2"));

        // Then
        assertThat(LlmChatTabPanel.sameTabComms(before, "m1", after, "m1"), is(true));
    }

    @Test
    void shouldTreatConfigsAsDifferentCommsWhenModelSelectionChanges() {
        // Given
        LlmProviderConfig config =
                new LlmProviderConfig(
                        "ollama",
                        LlmProvider.OLLAMA,
                        null,
                        "http://localhost",
                        List.of("m1", "m2"));

        // Then
        assertThat(LlmChatTabPanel.sameTabComms(config, "m1", config, "m2"), is(false));
    }

    @Test
    void shouldTreatConfigsAsDifferentCommsWhenEndpointChanges() {
        // Given
        LlmProviderConfig before =
                new LlmProviderConfig(
                        "ollama", LlmProvider.OLLAMA, null, "http://localhost", List.of("m1"));
        LlmProviderConfig after =
                new LlmProviderConfig(
                        "ollama",
                        LlmProvider.OLLAMA,
                        null,
                        "http://localhost:11434",
                        List.of("m1"));

        // Then
        assertThat(LlmChatTabPanel.sameTabComms(before, "m1", after, "m1"), is(false));
    }
}
