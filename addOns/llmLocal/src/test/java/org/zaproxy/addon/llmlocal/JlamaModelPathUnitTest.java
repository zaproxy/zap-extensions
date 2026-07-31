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

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class JlamaModelPathUnitTest {

    @TempDir Path tempDir;

    @Test
    void shouldAcceptDirectoryWithConfigJson() throws Exception {
        // Given
        Path modelDir = tempDir.resolve("TinyLlama");
        Files.createDirectories(modelDir);
        Files.writeString(modelDir.resolve("config.json"), "{}");

        // When / Then
        assertThat(JlamaModelPath.isValidModelDirectory(modelDir.toString()), is(true));
        assertThat(
                JlamaModelPath.normalize(modelDir.toString()),
                is(modelDir.toAbsolutePath().normalize()));
    }

    @Test
    void shouldRejectDirectoryWithoutConfigJson() throws Exception {
        // Given
        Path modelDir = tempDir.resolve("empty");
        Files.createDirectories(modelDir);

        // When / Then
        assertThat(JlamaModelPath.isValidModelDirectory(modelDir.toString()), is(false));
    }

    @Test
    void shouldResolveFileToParentDirectoryWhenConfigPresent() throws Exception {
        // Given
        Path modelDir = tempDir.resolve("model");
        Files.createDirectories(modelDir);
        Files.writeString(modelDir.resolve("config.json"), "{}");
        Path weight = modelDir.resolve("model.safetensors");
        Files.writeString(weight, "x");

        // When
        Path normalized = JlamaModelPath.normalize(weight.toString());

        // Then
        assertThat(normalized, is(modelDir.toAbsolutePath().normalize()));
        assertThat(JlamaModelPath.isValidModelDirectory(weight.toString()), is(true));
    }

    @Test
    void shouldReportSupportedJavaVersionConsistently() {
        assertThat(ExtensionLlmLocal.isSupportedJavaVersion(), is(Runtime.version().feature() >= 21));
    }

    @Test
    void toModelNameShouldReturnDirectoryName() {
        assertThat(
                JlamaModelPath.toModelName(Path.of("/tmp/llm-models/TinyLlama")), is("TinyLlama"));
    }

    @Test
    void toJlamaModelIdShouldMapFolderNameToOwnerSlashName() {
        assertThat(
                JlamaModelPath.toJlamaModelId("tjake_TinyLlama-1.1B-Chat-v1.0-Jlama-Q4"),
                is("tjake/TinyLlama-1.1B-Chat-v1.0-Jlama-Q4"));
        assertThat(
                JlamaModelPath.toJlamaModelId("tjake/TinyLlama-1.1B-Chat-v1.0-Jlama-Q4"),
                is("tjake/TinyLlama-1.1B-Chat-v1.0-Jlama-Q4"));
    }

    @Test
    void resolveModelDirectoryShouldMapOwnerSlashNameToLocalFolder() {
        assertThat(
                JlamaModelPath.resolveModelDirectory("tjake/TinyLlama-1.1B-Chat-v1.0-Jlama-Q4"),
                is(
                        JlamaModelPath.getModelsDirectory()
                                .resolve("tjake_TinyLlama-1.1B-Chat-v1.0-Jlama-Q4")
                                .toAbsolutePath()
                                .normalize()));
        assertThat(
                JlamaModelPath.resolveModelDirectory("tjake_TinyLlama-1.1B-Chat-v1.0-Jlama-Q4"),
                is(
                        JlamaModelPath.getModelsDirectory()
                                .resolve("tjake_TinyLlama-1.1B-Chat-v1.0-Jlama-Q4")
                                .toAbsolutePath()
                                .normalize()));
    }

    @Test
    void supportsToolsShouldDetectToolMentionsInChatTemplate() throws Exception {
        Path withTools = tempDir.resolve("with-tools");
        Files.createDirectories(withTools);
        Files.writeString(
                withTools.resolve("tokenizer_config.json"),
                "{\"chat_template\":\"{% if tools %}use tools{% endif %}\"}");

        Path withoutTools = tempDir.resolve("without-tools");
        Files.createDirectories(withoutTools);
        Files.writeString(
                withoutTools.resolve("tokenizer_config.json"),
                "{\"chat_template\":\"{% for message in messages %}{{ message }}{% endfor %}\"}");

        assertThat(JlamaModelPath.supportsTools(withTools.toString()), is(true));
        assertThat(JlamaModelPath.supportsTools(withoutTools.toString()), is(false));
        assertThat(JlamaModelPath.supportsTools(tempDir.resolve("missing").toString()), is(false));
    }
}
