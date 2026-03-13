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
package org.zaproxy.zap.extension.zest.exim;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.db.Database;
import org.parosproxy.paros.db.RecordHistory;
import org.parosproxy.paros.db.TableHistory;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.zaproxy.addon.exim.Exporter;
import org.zaproxy.addon.exim.ExporterOptions;
import org.zaproxy.addon.exim.ExporterResult;
import org.zaproxy.addon.exim.ExtensionExim;
import org.zaproxy.zap.extension.stats.InMemoryStats;
import org.zaproxy.zap.extension.zest.ExtensionZest;
import org.zaproxy.zap.extension.zest.ZestParam;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.Stats;

/** Unit test for {@link ZestExporter} and Zest export via {@link Exporter}. */
class ZestExporterUnitTest extends TestUtils {

    private static final String ZEST_SCRIPT_TITLE = "Exported from ZAP History";

    private long sessionId;
    private TableHistory tableHistory;
    private Path outputFile;
    private ExporterOptions options;
    private InMemoryStats stats;
    private Exporter exporter;
    private ExtensionExim extExim;

    @BeforeAll
    static void setupMessages() {
        mockMessages(new ExtensionExim(), new ExtensionZest());
    }

    @BeforeEach
    void setup(@TempDir Path dir) {
        outputFile = dir.resolve("output.zst");

        sessionId = 1234L;
        Session session = mock(Session.class, withSettings().strictness(Strictness.LENIENT));
        given(session.getSessionId()).willReturn(sessionId);

        tableHistory = mock(TableHistory.class, withSettings().strictness(Strictness.LENIENT));
        org.parosproxy.paros.model.HistoryReference.setTableHistory(tableHistory);

        Database db = mock(Database.class, withSettings().strictness(Strictness.LENIENT));
        given(db.getTableHistory()).willReturn(tableHistory);

        Model model = mock(Model.class, withSettings().strictness(Strictness.LENIENT));
        Model.setSingletonForTesting(model);
        given(model.getSession()).willReturn(session);
        given(model.getDb()).willReturn(db);

        ExtensionZest extZest =
                mock(ExtensionZest.class, withSettings().strictness(Strictness.LENIENT));
        ZestParam zestParam = mock(ZestParam.class);
        given(extZest.getParam()).willReturn(zestParam);
        given(extZest.convertElementToString(any()))
                .willAnswer(
                        invocation -> {
                            Object element = invocation.getArgument(0);
                            return element != null
                                    ? org.zaproxy.zest.core.v1.ZestJSON.toString(
                                            (org.zaproxy.zest.core.v1.ZestElement) element)
                                    : "{}";
                        });

        extExim = new ExtensionExim();
        extExim.registerExporterType(
                "zest", new ZestExporter(extZest), Constant.messages.getString("zest.exim.type"));

        options =
                ExporterOptions.builder()
                        .setContext(null)
                        .setType(ExporterOptions.Type.fromString("zest"))
                        .setSource(ExporterOptions.Source.HISTORY)
                        .setOutputFile(outputFile)
                        .build();

        stats = new InMemoryStats();
        Stats.addListener(stats);

        exporter = new Exporter(model);
    }

    @AfterEach
    void cleanup() {
        Stats.removeListener(stats);
        extExim.unregisterExporterType("zest");
    }

    @Test
    void shouldExportEmptyZestScriptIfNothingToExport() throws Exception {
        // Given
        given(tableHistory.getHistoryIdsOfHistType(anyLong(), any(int[].class)))
                .willReturn(java.util.List.of());

        // When
        ExporterResult result = exporter.export(options);

        // Then
        assertThat(result.getCount(), is(equalTo(0)));
        assertThat(result.getErrors(), is(empty()));
        assertThat(result.getCause(), is(nullValue()));
        String content = Files.readString(outputFile);
        assertThat(content, containsString(ZEST_SCRIPT_TITLE));
    }

    @Test
    void shouldExportHistoryToZest() throws Exception {
        // Given
        given(tableHistory.getHistoryIdsOfHistType(anyLong(), any(int[].class)))
                .willReturn(java.util.List.of(1));
        given(tableHistory.read(1))
                .willReturn(
                        new RecordHistory(
                                1,
                                42,
                                sessionId,
                                1L,
                                2,
                                "GET http://example.com/1 HTTP/1.1",
                                new byte[] {},
                                "HTTP/1.1 200 OK",
                                new byte[] {},
                                "",
                                "",
                                true));

        // When
        ExporterResult result = exporter.export(options);

        // Then
        assertThat(result.getCount(), is(equalTo(1)));
        assertThat(result.getErrors(), is(empty()));
        assertThat(result.getCause(), is(nullValue()));
        String content = Files.readString(outputFile);
        assertThat(content, containsString(ZEST_SCRIPT_TITLE));
        assertThat(content, containsString("http://example.com/1"));
    }
}
