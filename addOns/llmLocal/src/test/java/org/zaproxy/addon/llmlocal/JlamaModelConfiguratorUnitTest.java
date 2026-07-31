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
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.llm.ExtensionLlm;
import org.zaproxy.addon.llm.LlmProvider;
import org.zaproxy.addon.llm.LlmProviderConfig;
import org.zaproxy.addon.llm.LocalLlmModelPath;
import org.zaproxy.zap.testutils.TestUtils;

class JlamaModelConfiguratorUnitTest extends TestUtils {

    @BeforeAll
    static void setupAll() {
        mockMessages(new ExtensionLlmLocal());
    }

    @BeforeEach
    void setUp() throws Exception {
        setUpZap();
    }

    @Test
    void modelsDirectoryShouldBeUnderZapHome() {
        assertThat(
                JlamaModelConfigurator.getModelsDirectory(),
                is(Path.of(Constant.getZapHome(), "llm-models")));
    }

    @Test
    void configureProviderShouldUpsertJlamaDefaultWithAbsolutePath() {
        // Given
        ExtensionLlm extensionLlm = mock(ExtensionLlm.class);
        Path modelDir = Path.of("/tmp/llm-models/TinyLlama");

        // When
        JlamaModelConfigurator.configureProvider(extensionLlm, modelDir);

        // Then
        ArgumentCaptor<LlmProviderConfig> configCaptor =
                ArgumentCaptor.forClass(LlmProviderConfig.class);
        ArgumentCaptor<Boolean> defaultCaptor = ArgumentCaptor.forClass(Boolean.class);
        verify(extensionLlm).configureProvider(configCaptor.capture(), defaultCaptor.capture());

        LlmProviderConfig config = configCaptor.getValue();
        assertThat(config.getName(), is("Local"));
        assertThat(config.getProvider(), is(LlmProvider.JLAMA));
        assertThat(config.getModels(), hasSize(1));
        assertThat(
                config.getModels(),
                is(List.of(LocalLlmModelPath.toStoredModelId(modelDir.toString()))));
        assertThat(defaultCaptor.getValue(), is(true));
    }
}
