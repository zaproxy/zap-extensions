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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.zaproxy.addon.llm.LlmProvider;
import org.zaproxy.addon.llm.LlmProviderConfig;
import org.zaproxy.zap.testutils.TestUtils;

class JlamaLlmChatModelFactoryUnitTest extends TestUtils {

    @BeforeAll
    static void setupAll() {
        mockMessages(new ExtensionLlmLocal());
    }

    @Test
    void shouldReportJlamaProvider() {
        assertThat(new JlamaLlmChatModelFactory().getProvider(), is(LlmProvider.JLAMA));
    }

    @Test
    void shouldRejectInvalidModelPath() {
        // Given
        JlamaLlmChatModelFactory factory = new JlamaLlmChatModelFactory();
        LlmProviderConfig config =
                new LlmProviderConfig("jlama", LlmProvider.JLAMA, "", "", java.util.List.of());

        // When / Then
        assertThrows(
                IllegalArgumentException.class,
                () -> factory.create(config, "/does/not/exist", null, false));
    }
}
