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

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.EnumSource.Mode;
import org.junit.jupiter.params.provider.NullSource;
import org.zaproxy.addon.llm.ExtensionLlm;
import org.zaproxy.addon.llm.LlmProvider;
import org.zaproxy.zap.testutils.TestUtils;

class AddLlmProviderDialogUnitTest extends TestUtils {

    @BeforeAll
    static void setupAll() {
        mockMessages(new ExtensionLlm());
    }

    @Test
    void shouldApplyDefaultForOpenRouter() {
        // Given / When
        String endpoint = AddLlmProviderDialog.endpointValueOnSelect(LlmProvider.OPENROUTER);

        // Then
        assertThat(endpoint, is("https://openrouter.ai/api/v1"));
    }

    @ParameterizedTest
    @NullSource
    @EnumSource(
            value = LlmProvider.class,
            mode = Mode.EXCLUDE,
            names = {"OPENROUTER"})
    void shouldClearValueForProvidersWithoutDefaultEndpoint(LlmProvider provider) {
        // Given / When
        String endpoint = AddLlmProviderDialog.endpointValueOnSelect(provider);
        // Then
        assertThat(endpoint, is(""));
    }
}
