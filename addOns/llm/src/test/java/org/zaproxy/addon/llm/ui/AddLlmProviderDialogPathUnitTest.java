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

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class AddLlmProviderDialogPathUnitTest {

    @TempDir Path tempDir;

    @Test
    void shouldNormalizeFileToParentModelDirectory() throws Exception {
        // Given
        Path modelDir = tempDir.resolve("local-model");
        Files.createDirectories(modelDir);
        Files.writeString(modelDir.resolve("config.json"), "{}");
        Path file = modelDir.resolve("weights.safetensors");
        Files.writeString(file, "x");

        // When
        Path normalized = AddLlmProviderDialog.normalizeLocalModelPath(file.toString());

        // Then
        assertThat(normalized, is(modelDir.toAbsolutePath().normalize()));
        assertThat(AddLlmProviderDialog.isValidLocalModelPath(file.toString()), is(true));
    }

    @Test
    void shouldRejectMissingConfig() throws Exception {
        // Given
        Path modelDir = tempDir.resolve("incomplete");
        Files.createDirectories(modelDir);

        // When / Then
        assertThat(AddLlmProviderDialog.isValidLocalModelPath(modelDir.toString()), is(false));
    }
}
