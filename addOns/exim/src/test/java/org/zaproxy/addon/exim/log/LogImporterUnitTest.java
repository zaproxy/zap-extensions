/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.addon.exim.log;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.zaproxy.addon.commonlib.ui.ProgressPaneListener;
import org.zaproxy.addon.exim.log.LogsImporter.LogType;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit test for {@link LogImporter}. */
class LogImporterUnitTest extends TestUtils {

    @ParameterizedTest
    @ValueSource(
            strings = {
                "threeEqualsNoSpace.txt",
                "fourEqualsNoSpace.txt",
                "threeEqualsSpace.txt",
                "fourEqualsSpace.txt"
            })
    void shouldReadZapMessagesFileWithVariousDelimiters(String fileName) throws IOException {
        // Given
        File file = getResourcePath(fileName).toFile();
        // When
        List<String> parsed = LogsImporter.readFile(file);
        // Then
        assertThat(parsed.size(), is(equalTo(2)));
    }

    private Path generateTestFile(int countSamples) throws IOException {
        String template =
                "==== @@@ ==========\n"
                        + "GET http://example.org/@@@ HTTP/1.1\n"
                        + "Host: example.org\n"
                        + "\n"
                        + "\n"
                        + "HTTP/1.1 200 OK\n"
                        + "Content-Type: text/html\n"
                        + "content-length: 40\n"
                        + "\n"
                        + "<!DOCTYPE html>\n"
                        + "<html lang=\"en\">\n"
                        + "</html>\n";
        StringBuilder builder = new StringBuilder(template.length() * countSamples);
        Path path = Files.createTempFile("samples", "txt");
        for (int i = 0; i < countSamples; i++) {
            builder.append(template.replace("@@@", String.valueOf(i)));
        }
        Files.writeString(path, builder.subSequence(0, builder.length()));
        return path;
    }

    @Test
    void shouldReadLotsOfMessages() throws IOException {
        // Given
        File file = generateTestFile(110).toFile();
        // When
        List<String> parsed = LogsImporter.readFile(file);
        // Then
        assertThat(parsed.size(), is(equalTo(110)));
    }

    @Test
    void shouldBeFailureIfFileNotFound(@TempDir Path dir) throws Exception {
        // Given
        File file = dir.resolve("missing.raw").toFile();
        // When
        LogsImporter importer = new LogsImporter(file, LogType.ZAP);
        // Then
        assertThat(importer.isSuccess(), equalTo(false));
    }

    @Test
    void shouldCompleteListenerIfFileNotFound(@TempDir Path dir) throws Exception {
        // Given
        File file = dir.resolve("missing.raw").toFile();
        ProgressPaneListener listener = mock(ProgressPaneListener.class);
        // When
        LogsImporter importer = new LogsImporter(file, LogType.ZAP, listener);
        // Then
        assertThat(importer.isSuccess(), equalTo(false));
        verify(listener).completed();
    }

    @Test
    void shouldBeFailureIfFileNotFoundModSec2(@TempDir Path dir) throws Exception {
        // Given
        File file = dir.resolve("missing.log").toFile();
        // When
        LogsImporter importer = new LogsImporter(file, LogType.MOD_SECURITY_2);
        // Then
        assertThat(importer.isSuccess(), equalTo(false));
    }

    @Test
    void shouldCompleteListenerIfFileNotFoundModSec2(@TempDir Path dir) throws Exception {
        // Given
        File file = dir.resolve("missing.log").toFile();
        ProgressPaneListener listener = mock(ProgressPaneListener.class);
        // When
        LogsImporter importer = new LogsImporter(file, LogType.MOD_SECURITY_2, listener);
        // Then
        assertThat(importer.isSuccess(), equalTo(false));
        verify(listener).completed();
    }
}
