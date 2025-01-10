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
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.startsWith;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.withSettings;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.MockSettings;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.db.Database;
import org.parosproxy.paros.db.RecordHistory;
import org.parosproxy.paros.db.TableHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.zaproxy.addon.exim.ExporterOptions.Source;
import org.zaproxy.addon.exim.ExporterOptions.Type;
import org.zaproxy.zap.extension.stats.InMemoryStats;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.Stats;

/** Unit test for {@link Exporter}. */
class ExporterUnitTest extends TestUtils {

    private static final MockSettings LENIENT = withSettings().strictness(Strictness.LENIENT);
    private long sessionId;
    private TableHistory tableHistory;
    private Path outputDir;
    private Path outputFile;
    private ExporterOptions options;
    private InMemoryStats stats;

    private Exporter exporter;

    @BeforeAll
    static void setupMessages() {
        mockMessages(new ExtensionExim());
    }

    @BeforeEach
    void setup(@TempDir Path dir) {
        outputDir = dir;
        outputFile = dir.resolve("outputfile");

        sessionId = 1234L;
        Session session = mock(Session.class, LENIENT);
        given(session.getSessionId()).willReturn(sessionId);

        tableHistory = mock(TableHistory.class, LENIENT);
        HistoryReference.setTableHistory(tableHistory);

        Database db = mock(Database.class, LENIENT);
        given(db.getTableHistory()).willReturn(tableHistory);

        Model model = mock(Model.class, LENIENT);
        Model.setSingletonForTesting(model);
        given(model.getSession()).willReturn(session);
        given(model.getDb()).willReturn(db);

        options = mock(ExporterOptions.class, LENIENT);
        optionsWithType(Type.HAR);
        optionsWithSource(Source.HISTORY);
        given(options.getOutputFile()).willReturn(outputFile);

        stats = new InMemoryStats();
        Stats.addListener(stats);

        exporter = new Exporter(model);
    }

    @AfterEach
    void cleanup() {
        Stats.removeListener(stats);
    }

    private void optionsWithType(Type type) {
        given(options.getType()).willReturn(type);
    }

    private void optionsWithSource(Source source) {
        given(options.getSource()).willReturn(source);
    }

    private void databaseWithHistoryMessage() throws Exception {
        databaseWithMessageForTypes(HistoryReference.TYPE_PROXIED, HistoryReference.TYPE_ZAP_USER);
    }

    private void databaseWithAllMessage() throws Exception {
        databaseWithMessageForTypes();
    }

    private void databaseWithMessageForTypes(int... types) throws Exception {
        given(tableHistory.getHistoryIdsOfHistType(sessionId, types)).willReturn(List.of(1));

        given(tableHistory.read(1))
                .willReturn(
                        new RecordHistory(
                                1,
                                42,
                                sessionId,
                                1L,
                                2,
                                "GET http://example.com/1 HTTP/1.1",
                                new byte[] {0x01},
                                "HTTP/1.1 200",
                                new byte[] {0x02},
                                "",
                                "note 1",
                                true));
    }

    @Test
    void shouldExportEmptyHarIfNothingToExport() throws Exception {
        // Given
        optionsWithType(Type.HAR);
        // When
        ExporterResult result = exporter.export(options);
        // Then
        assertCount(result, 0);
        assertThat(result.getErrors(), is(empty()));
        assertThat(result.getCause(), is(nullValue()));
        assertThat(
                Files.readString(outputFile),
                is(
                        equalTo(
                                "{\n"
                                        + "  \"log\" : {\n"
                                        + "    \"version\" : \"1.2\",\n"
                                        + "    \"creator\" : {\n"
                                        + "      \"name\" : \"ZAP\",\n"
                                        + "      \"version\" : \"Dev Build\"\n"
                                        + "    },\n"
                                        + "    \"entries\" : [ ]\n"
                                        + "  }\n"
                                        + "}")));
    }

    @Test
    void shouldExportHistoryToHar() throws Exception {
        // Given
        optionsWithType(Type.HAR);
        databaseWithHistoryMessage();
        // When
        ExporterResult result = exporter.export(options);
        // Then
        assertCount(result, 1);
        assertThat(result.getErrors(), is(empty()));
        assertThat(result.getCause(), is(nullValue()));
        assertThat(
                Files.readString(outputFile),
                containsString("\"url\" : \"http://example.com/1\",\n"));
    }

    private void assertCount(ExporterResult result, int count) {
        assertThat(result.getCount(), is(equalTo(count)));
        assertThat(
                stats.getStat("stats.exim.exporter." + options.getType().getId() + ".count"),
                is(equalTo((long) count)));
    }

    @Test
    void shouldExportAllToHar() throws Exception {
        // Given
        optionsWithType(Type.HAR);
        optionsWithSource(Source.ALL);
        databaseWithAllMessage();
        // When
        ExporterResult result = exporter.export(options);
        // Then
        assertCount(result, 1);
        assertThat(result.getErrors(), is(empty()));
        assertThat(result.getCause(), is(nullValue()));
        assertThat(
                Files.readString(outputFile),
                containsString("\"url\" : \"http://example.com/1\",\n"));
    }

    @Test
    void shouldExportNoUrlsIfNothingToExport() throws Exception {
        // Given
        optionsWithType(Type.URL);
        // When
        ExporterResult result = exporter.export(options);
        // Then
        assertCount(result, 0);
        assertThat(result.getErrors(), is(empty()));
        assertThat(result.getCause(), is(nullValue()));
        assertThat(Files.readString(outputFile), is(equalTo("")));
    }

    @Test
    void shouldExportHistoryToUrls() throws Exception {
        // Given
        optionsWithType(Type.URL);
        databaseWithHistoryMessage();
        // When
        ExporterResult result = exporter.export(options);
        // Then
        assertCount(result, 1);
        assertThat(result.getErrors(), is(empty()));
        assertThat(result.getCause(), is(nullValue()));
        assertThat(Files.readString(outputFile), is(equalTo("http://example.com/1\n")));
    }

    @Test
    void shouldExportAllToUrls() throws Exception {
        // Given
        optionsWithType(Type.URL);
        optionsWithSource(Source.ALL);
        databaseWithAllMessage();
        // When
        ExporterResult result = exporter.export(options);
        // Then
        assertCount(result, 1);
        assertThat(result.getErrors(), is(empty()));
        assertThat(result.getCause(), is(nullValue()));
        assertThat(Files.readString(outputFile), is(equalTo("http://example.com/1\n")));
    }

    @Test
    void shouldErrorIfOutputFileNotValid() {
        // Given
        given(options.getOutputFile()).willReturn(outputDir);
        // When
        ExporterResult result = exporter.export(options);
        // Then
        assertCount(result, 0);
        assertThat(result.getErrors(), contains(startsWith("Cannot write to non-file: ")));
        assertThat(result.getCause(), is(nullValue()));
        assertThat(Files.notExists(outputFile), is(equalTo(true)));
    }

    @Test
    void shouldErrorIfParentOutputFileNotValid() {
        // Given
        given(options.getOutputFile()).willReturn(Paths.get("/parent/invalid/outputfile"));
        // When
        ExporterResult result = exporter.export(options);
        // Then
        assertCount(result, 0);
        assertThat(
                result.getErrors(),
                contains(startsWith("Cannot write file to nonexistent directory: ")));
        assertThat(result.getCause(), is(nullValue()));
        assertThat(Files.notExists(outputFile), is(equalTo(true)));
    }

    @ParameterizedTest
    @EnumSource(
            value = Type.class,
            names = {"HAR", "URL"})
    void shouldIncludeMessageInContext(Type type) throws Exception {
        // Given
        optionsWithType(type);
        databaseWithHistoryMessage();
        Context context = mock(Context.class);
        given(options.getContext()).willReturn(context);
        given(context.isInContext(any(HistoryReference.class))).willReturn(true);
        // When
        ExporterResult result = exporter.export(options);
        // Then
        assertCount(result, 1);
        assertThat(result.getErrors(), is(empty()));
        assertThat(result.getCause(), is(nullValue()));
        assertThat(Files.readString(outputFile), containsString("http://example.com/1"));
        verify(context).isInContext(any(HistoryReference.class));
    }

    @ParameterizedTest
    @EnumSource(
            value = Type.class,
            names = {"HAR", "URL"})
    void shouldNotIncludeMessageNotInContext(Type type) throws Exception {
        // Given
        optionsWithType(type);
        databaseWithHistoryMessage();
        Context context = mock(Context.class);
        given(options.getContext()).willReturn(context);
        given(context.isInContext(any(HistoryReference.class))).willReturn(false);
        // When
        ExporterResult result = exporter.export(options);
        // Then
        assertCount(result, 0);
        assertThat(result.getErrors(), is(empty()));
        assertThat(result.getCause(), is(nullValue()));
        assertThat(Files.readString(outputFile), not(containsString("http://example.com/1")));
        verify(context).isInContext(any(HistoryReference.class));
    }

    @ParameterizedTest
    @EnumSource(
            value = Type.class,
            names = {"HAR", "URL"})
    void shouldFailSiteTreeExportWithNonYamlFormat(Type type) throws Exception {
        // Given
        optionsWithType(type);
        optionsWithSource(Source.SITESTREE);
        // When
        ExporterResult result = exporter.export(options);
        // Then
        assertCount(result, 0);
        assertThat(result.getErrors().size(), is(1));
        assertThat(
                result.getErrors().get(0),
                is("Invalid type for SitesTree, only YAML is supported: " + type));
        assertThat(result.getCause(), is(nullValue()));
    }

    @ParameterizedTest
    @EnumSource(
            value = Source.class,
            names = {"HISTORY", "ALL"})
    void shouldFailNonSitesTreeExportWithYamlFormat(Source source) throws Exception {
        // Given
        optionsWithType(Type.YAML);
        optionsWithSource(source);
        // When
        ExporterResult result = exporter.export(options);
        // Then
        assertCount(result, 0);
        assertThat(result.getErrors().size(), is(1));
        assertThat(
                result.getErrors().get(0),
                is("Invalid type for " + source + ", YAML is not supported"));
        assertThat(result.getCause(), is(nullValue()));
    }
}
