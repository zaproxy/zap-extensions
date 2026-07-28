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
import static org.hamcrest.Matchers.is;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.testutils.TestUtils;

class LocalLlmModelPathUnitTest extends TestUtils {

    @TempDir Path tempDir;

    @BeforeAll
    static void setupAll() {
        mockMessages(new ExtensionLlm());
    }

    @BeforeEach
    void setUp() throws Exception {
        setUpZap();
    }

    @Test
    void shouldResolveOwnerSlashNameToLocalFolder() {
        assertThat(
                LocalLlmModelPath.resolveModelDirectory("tjake/TinyLlama-1.1B-Chat-v1.0-Jlama-Q4"),
                is(
                        Path.of(
                                        Constant.getZapHome(),
                                        LlmProvider.LOCAL_MODELS_DIR,
                                        "tjake_TinyLlama-1.1B-Chat-v1.0-Jlama-Q4")
                                .toAbsolutePath()
                                .normalize()));
    }

    @Test
    void shouldStoreAbsolutePathForOwnerSlashName() throws Exception {
        Path modelDir =
                Path.of(
                        Constant.getZapHome(),
                        LlmProvider.LOCAL_MODELS_DIR,
                        "tjake_TinyLlama-1.1B-Chat-v1.0-Jlama-Q4");
        Files.createDirectories(modelDir);
        Files.writeString(modelDir.resolve("config.json"), "{}");

        assertThat(
                LocalLlmModelPath.toStoredModelId("tjake/TinyLlama-1.1B-Chat-v1.0-Jlama-Q4"),
                is(modelDir.toAbsolutePath().normalize().toString()));
        assertThat(
                LocalLlmModelPath.toDisplayName("tjake/TinyLlama-1.1B-Chat-v1.0-Jlama-Q4"),
                is("tjake_TinyLlama-1.1B-Chat-v1.0-Jlama-Q4"));
        assertThat(
                LocalLlmModelPath.isValidModelDirectory("tjake/TinyLlama-1.1B-Chat-v1.0-Jlama-Q4"),
                is(true));
    }

    @Test
    void shouldStoreAbsolutePathForBareName() throws Exception {
        Path modelDir = Path.of(Constant.getZapHome(), LlmProvider.LOCAL_MODELS_DIR, "TinyLlama");
        Files.createDirectories(modelDir);
        Files.writeString(modelDir.resolve("config.json"), "{}");

        assertThat(
                LocalLlmModelPath.toStoredModelId("TinyLlama"),
                is(modelDir.toAbsolutePath().normalize().toString()));
        assertThat(LocalLlmModelPath.toDisplayName("TinyLlama"), is("TinyLlama"));
    }

    @Test
    void shouldStoreAbsolutePathAsIs() throws Exception {
        Path modelDir = tempDir.resolve("elsewhere").resolve("custom-model");
        Files.createDirectories(modelDir);
        Files.writeString(modelDir.resolve("config.json"), "{}");

        String absolute = modelDir.toAbsolutePath().normalize().toString();
        assertThat(LocalLlmModelPath.toStoredModelId(absolute), is(absolute));
        assertThat(LocalLlmModelPath.toDisplayName(absolute), is("custom-model"));
    }

    @Test
    void shouldNormalizeAbsoluteFileToParent() throws Exception {
        Path modelDir = tempDir.resolve("local-model");
        Files.createDirectories(modelDir);
        Files.writeString(modelDir.resolve("config.json"), "{}");
        Path file = modelDir.resolve("weights.safetensors");
        Files.writeString(file, "x");

        assertThat(
                LocalLlmModelPath.resolveModelDirectory(file.toString()),
                is(modelDir.toAbsolutePath().normalize()));
    }
}
