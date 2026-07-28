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

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

class JlamaModelDownloaderUnitTest {

    @Test
    void defaultTestModelShouldBeToolCapableInstructModel() {
        assertThat(
                JlamaModelDownloader.DEFAULT_TEST_MODEL,
                is("tjake/Llama-3.2-1B-Instruct-Jlama-Q4"));
    }

    @Test
    void shouldRejectNullCacheDir() {
        assertThrows(
                NullPointerException.class,
                () -> JlamaModelDownloader.download(null, JlamaModelDownloader.DEFAULT_TEST_MODEL));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "a/b/c", "/name", "owner/", "//"})
    void shouldRejectInvalidModelId(String modelId) {
        assertThrows(
                IllegalArgumentException.class,
                () -> JlamaModelDownloader.validateModelId(modelId));
    }

    @Test
    void shouldAcceptOwnerSlashName() {
        JlamaModelDownloader.validateModelId("tjake/TinyLlama-1.1B-Chat-v1.0-Jlama-Q4");
    }

    @Test
    void downloadShouldRejectBlankModelWithoutNetwork() {
        Path cache = Path.of("build", "jlama-test-models");
        assertThrows(
                IllegalArgumentException.class, () -> JlamaModelDownloader.download(cache, "  "));
    }

    @Test
    void shouldDeleteIncompleteDownload(@TempDir Path temp) throws Exception {
        Path modelDir = temp.resolve("tjake_Incomplete");
        Files.createDirectories(modelDir);
        Path partial = modelDir.resolve("model.safetensors");
        Files.writeString(partial, "partial");

        JlamaModelDownloader.deleteIncompleteDownload(modelDir);

        assertThat(Files.exists(modelDir), is(false));
        assertThat(Files.exists(partial), is(false));
    }

    @Test
    void shouldNotDeleteCompleteDownload(@TempDir Path temp) throws Exception {
        Path modelDir = temp.resolve("tjake_Complete");
        Files.createDirectories(modelDir);
        Path finished = modelDir.resolve(JlamaModelDownloader.FINISHED_MARKER);
        Files.createFile(finished);
        Path weights = modelDir.resolve("model.safetensors");
        Files.writeString(weights, "complete");

        JlamaModelDownloader.deleteIncompleteDownload(modelDir);

        assertThat(Files.isDirectory(modelDir), is(true));
        assertThat(Files.exists(finished), is(true));
        assertThat(Files.exists(weights), is(true));
    }
}
