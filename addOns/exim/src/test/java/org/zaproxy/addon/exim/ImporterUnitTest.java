/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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
package org.zaproxy.addon.exim;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.startsWith;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.withSettings;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.exim.ImporterOptions.Type;
import org.zaproxy.zap.extension.stats.InMemoryStats;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.Stats;

/** Unit test for {@link Importer}. */
class ImporterUnitTest extends TestUtils {

    private Path inputDir;
    private Path inputFile;
    private ImporterOptions options;
    private InMemoryStats stats;
    private List<HttpMessage> importedMessages;

    private Importer importer;

    @BeforeAll
    static void setupMessages() {
        mockMessages(new ExtensionExim());
    }

    @BeforeEach
    void setup(@TempDir Path dir) {
        inputDir = dir;
        inputFile = dir.resolve("inputfile");

        options = mock(ImporterOptions.class, withSettings().strictness(Strictness.LENIENT));
        optionsWithType(Type.HAR);
        given(options.getInputFile()).willReturn(inputFile);
        importedMessages = new ArrayList<>();
        given(options.getMessageHandler()).willReturn(this::importedMessage);

        stats = new InMemoryStats();
        Stats.addListener(stats);

        importer = new Importer();
    }

    private void importedMessage(HttpMessage message) {
        importedMessages.add(message);
    }

    @AfterEach
    void cleanup() {
        Stats.removeListener(stats);
    }

    private void optionsWithType(Type type) {
        given(options.getType()).willReturn(type);
    }

    @Test
    void shouldNotImportAnythingIfEmptyHar() throws Exception {
        // Given
        optionsWithType(Type.HAR);
        inputFileWith(
                "{\n"
                        + "  \"log\" : {\n"
                        + "    \"version\" : \"1.2\",\n"
                        + "    \"creator\" : {\n"
                        + "      \"name\" : \"ZAP\",\n"
                        + "      \"version\" : \"Dev Build\"\n"
                        + "    },\n"
                        + "    \"entries\" : [ ]\n"
                        + "  }\n"
                        + "}");
        // When
        ImporterResult result = importer.apply(options);
        // Then
        assertCount(result, 0);
        assertThat(result.getErrors(), is(empty()));
        assertThat(result.getCause(), is(nullValue()));
    }

    private void inputFileWith(String content) throws IOException {
        Files.writeString(inputFile, content);
    }

    @Test
    void shouldImportFromHar() throws Exception {
        // Given
        optionsWithType(Type.HAR);
        inputFileWith(
                "{\n"
                        + "  \"log\" : {\n"
                        + "    \"entries\" : [ {\n"
                        + "      \"request\" : {\n"
                        + "        \"method\" : \"GET\",\n"
                        + "        \"url\" : \"http://example.com\",\n"
                        + "        \"httpVersion\" : \"HTTP/1.1\"\n"
                        + "      },\n"
                        + "      \"response\" : {\n"
                        + "        \"status\" : 0\n"
                        + "      }\n"
                        + "    } ]\n"
                        + "  }\n"
                        + "}");
        // When
        ImporterResult result = importer.apply(options);
        // Then
        assertCount(result, 1);
        assertThat(result.getErrors(), is(empty()));
        assertThat(result.getCause(), is(nullValue()));
        assertThat(importedMessages, hasSize(1));
        HttpMessage importedMessage = importedMessages.get(0);
        assertThat(
                importedMessage.getRequestHeader().getURI().toString(),
                is(equalTo("http://example.com")));
    }

    private void assertCount(ImporterResult result, int count) {
        assertThat(result.getCount(), is(equalTo(count)));
        assertThat(
                stats.getStat("stats.exim.importer." + options.getType().getId() + ".count"),
                is(equalTo((long) count)));
    }

    @Test
    void shouldErrorIfInputFileNotValid() {
        // Given
        given(options.getInputFile()).willReturn(inputDir);
        // When
        ImporterResult result = importer.apply(options);
        // Then
        assertCount(result, 0);
        assertThat(result.getErrors(), contains(startsWith("Cannot read from non-file: ")));
        assertThat(result.getCause(), is(nullValue()));
    }

    @Test
    void shouldErrorIfInputFileDoesNotExist() {
        // Given
        given(options.getInputFile()).willReturn(Paths.get("/not-exists"));
        // When
        ImporterResult result = importer.apply(options);
        // Then
        assertCount(result, 0);
        assertThat(result.getErrors(), contains(startsWith("Cannot read from nonexistent file: ")));
        assertThat(result.getCause(), is(nullValue()));
    }

    @Test
    void shouldIncludeMessageInContext() throws Exception {
        // Given
        optionsWithType(Type.HAR);
        inputFileWith(
                "{\n"
                        + "  \"log\" : {\n"
                        + "    \"entries\" : [ {\n"
                        + "      \"request\" : {\n"
                        + "        \"method\" : \"GET\",\n"
                        + "        \"url\" : \"http://example.com/1\",\n"
                        + "        \"httpVersion\" : \"HTTP/1.1\"\n"
                        + "      }\n"
                        + "    } ]\n"
                        + "  }\n"
                        + "}");
        Context context = mock(Context.class);
        given(options.getContext()).willReturn(context);
        given(context.isInContext(anyString())).willReturn(true);
        // When
        ImporterResult result = importer.apply(options);
        // Then
        assertCount(result, 1);
        assertThat(result.getErrors(), is(empty()));
        assertThat(result.getCause(), is(nullValue()));
        assertThat(importedMessages, hasSize(1));
        assertThat(
                importedMessages.get(0).getRequestHeader().getURI().toString(),
                is(equalTo("http://example.com/1")));
        verify(context).isInContext(anyString());
    }

    @Test
    void shouldNotIncludeMessageNotInContext() throws Exception {
        // Given
        optionsWithType(Type.HAR);
        inputFileWith(
                "{\n"
                        + "  \"log\" : {\n"
                        + "    \"entries\" : [ {\n"
                        + "      \"request\" : {\n"
                        + "        \"method\" : \"GET\",\n"
                        + "        \"url\" : \"http://example.com/1\",\n"
                        + "        \"httpVersion\" : \"HTTP/1.1\"\n"
                        + "      }\n"
                        + "    } ]\n"
                        + "  }\n"
                        + "}");
        Context context = mock(Context.class);
        given(options.getContext()).willReturn(context);
        given(context.isInContext(anyString())).willReturn(false);
        // When
        ImporterResult result = importer.apply(options);
        // Then
        assertCount(result, 0);
        assertThat(result.getErrors(), is(empty()));
        assertThat(result.getCause(), is(nullValue()));
        assertThat(importedMessages, hasSize(0));
        verify(context).isInContext(anyString());
    }
}
