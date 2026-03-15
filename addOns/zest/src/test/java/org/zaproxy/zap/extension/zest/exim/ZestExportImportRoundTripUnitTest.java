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
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.db.Database;
import org.parosproxy.paros.db.RecordHistory;
import org.parosproxy.paros.db.TableAlert;
import org.parosproxy.paros.db.TableHistory;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.model.SiteMap;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.exim.Exporter;
import org.zaproxy.addon.exim.ExporterOptions;
import org.zaproxy.addon.exim.ExporterResult;
import org.zaproxy.addon.exim.ExtensionExim;
import org.zaproxy.zap.extension.stats.InMemoryStats;
import org.zaproxy.zap.extension.zest.ExtensionZest;
import org.zaproxy.zap.extension.zest.ZestParam;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.Stats;

/** Unit test for Zest export then import round-trip. */
@MockitoSettings(strictness = Strictness.LENIENT)
class ZestExportImportRoundTripUnitTest extends TestUtils {

    private static final byte[] EMPTY_BODY = {};

    private static TableHistory tableHistory;
    private static Session session;
    private static long sessionId;
    private static ExtensionLoader extensionLoader;
    private static ExtensionHistory extHistory;
    private static SiteMap siteMap;

    private Path outputFile;
    private ExporterOptions options;
    private InMemoryStats stats;
    private Exporter exporter;
    private List<HttpMessage> importedMessages;
    private ExtensionExim extExim;

    @BeforeAll
    static void setupAll() throws Exception {
        mockMessages(new ExtensionExim(), new ExtensionZest());

        sessionId = 1234L;
        session = mock(Session.class, withSettings().strictness(Strictness.LENIENT));
        given(session.getSessionId()).willReturn(sessionId);

        tableHistory = mock(TableHistory.class, withSettings().strictness(Strictness.LENIENT));
        HistoryReference.setTableHistory(tableHistory);
        HistoryReference.setTableAlert(mock(TableAlert.class));

        Model model = mock(Model.class, withSettings().strictness(Strictness.LENIENT));
        Model.setSingletonForTesting(model);
        given(model.getSession()).willReturn(session);

        Database db = mock(Database.class, withSettings().strictness(Strictness.LENIENT));
        given(db.getTableHistory()).willReturn(tableHistory);
        given(model.getDb()).willReturn(db);

        extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        extHistory = mock(ExtensionHistory.class);
        given(extensionLoader.getExtension(ExtensionHistory.class)).willReturn(extHistory);
        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);

        siteMap = mock(SiteMap.class);
        given(session.getSiteTree()).willReturn(siteMap);
    }

    @BeforeEach
    void setup(@TempDir Path dir) throws Exception {
        outputFile = dir.resolve("output.zst");
        importedMessages = new ArrayList<>();

        given(tableHistory.write(anyLong(), anyInt(), any()))
                .willAnswer(
                        invocation -> {
                            Object arg = invocation.getArgument(2);
                            if (arg instanceof HttpMessage) {
                                importedMessages.add((HttpMessage) arg);
                            }
                            return mock(RecordHistory.class);
                        });

        ExtensionZest extZest =
                mock(ExtensionZest.class, withSettings().strictness(Strictness.LENIENT));
        ZestParam zestParam = mock(ZestParam.class);
        given(extZest.getParam()).willReturn(zestParam);
        given(zestParam.isIncludeResponses()).willReturn(true);
        given(zestParam.getIgnoredHeaders()).willReturn(List.of());
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

        exporter = new Exporter(Model.getSingleton());
    }

    @AfterEach
    void cleanup() {
        Stats.removeListener(stats);
        extExim.unregisterExporterType("zest");
    }

    @AfterAll
    static void cleanupAll() {
        Constant.messages = null;
        HistoryReference.setTableHistory(null);
        HistoryReference.setTableAlert(null);
    }

    @Test
    void shouldExportAndImportMultipleMessagesIncludingPostWithBody() throws Exception {
        // Given - three messages: GET, POST with body, GET
        String getRequestHeader1 =
                "GET http://example.com/page1 HTTP/1.1\r\nHost: example.com\r\n\r\n";
        String postRequestHeader =
                "POST http://example.com/login HTTP/1.1\r\nHost: example.com\r\n"
                        + "Content-Type: application/x-www-form-urlencoded\r\n"
                        + "Content-Length: 15\r\n\r\n";
        byte[] postBody = "user=foo&pass=bar".getBytes();
        String getRequestHeader2 =
                "GET http://example.com/page2 HTTP/1.1\r\nHost: example.com\r\n\r\n";
        String responseHeader = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";
        byte[] responseBody = "<html>ok</html>".getBytes();

        HttpMessage msg1 =
                new HttpMessage(getRequestHeader1, EMPTY_BODY, responseHeader, responseBody);
        msg1.setResponseFromTargetHost(true);
        HttpMessage msg2 =
                new HttpMessage(postRequestHeader, postBody, responseHeader, responseBody);
        msg2.setResponseFromTargetHost(true);
        HttpMessage msg3 =
                new HttpMessage(getRequestHeader2, EMPTY_BODY, responseHeader, responseBody);
        msg3.setResponseFromTargetHost(true);

        RecordHistory rec1 = mock(RecordHistory.class);
        RecordHistory rec2 = mock(RecordHistory.class);
        RecordHistory rec3 = mock(RecordHistory.class);
        given(rec1.getHttpMessage()).willReturn(msg1);
        given(rec2.getHttpMessage()).willReturn(msg2);
        given(rec3.getHttpMessage()).willReturn(msg3);
        given(rec1.getHistoryType()).willReturn(HistoryReference.TYPE_PROXIED);
        given(rec2.getHistoryType()).willReturn(HistoryReference.TYPE_PROXIED);
        given(rec3.getHistoryType()).willReturn(HistoryReference.TYPE_PROXIED);

        given(tableHistory.getHistoryIdsOfHistType(anyLong(), any(int[].class)))
                .willReturn(List.of(1, 2, 3));
        given(tableHistory.read(1)).willReturn(rec1);
        given(tableHistory.read(2)).willReturn(rec2);
        given(tableHistory.read(3)).willReturn(rec3);

        // When - export then import
        ExporterResult result = exporter.export(options);
        String exportedContent = Files.readString(outputFile);
        ZestImporter importer = new ZestImporter(outputFile.toFile());

        // Then - verify export produced valid file and import succeeded
        assertThat(result.getCount(), is(equalTo(3)));
        assertThat(exportedContent, containsString("http://example.com/page1"));
        assertThat(exportedContent, containsString("http://example.com/login"));
        assertThat(exportedContent, containsString("foo"));
        assertThat(exportedContent, containsString("bar"));
        assertThat(importer.isSuccess(), is(equalTo(true)));
        assertThat(importedMessages, hasSize(3));

        assertMessagesEqual(msg1, importedMessages.get(0));
        assertMessagesEqual(msg2, importedMessages.get(1));
        assertMessagesEqual(msg3, importedMessages.get(2));
    }

    @Test
    void shouldImportMultipleMessagesIncludingPostFromFile() throws Exception {
        // Given - Zest file with GET, POST with body, GET
        java.io.File zestFile = getResourcePath("multipleRequestsWithPost.zst").toFile();

        // When
        ZestImporter importer = new ZestImporter(zestFile);

        // Then
        assertThat(importer.isSuccess(), is(equalTo(true)));
        assertThat(importedMessages, hasSize(3));

        HttpMessage get1 = importedMessages.get(0);
        assertThat(get1.getRequestHeader().getMethod(), is(equalTo("GET")));
        assertThat(
                get1.getRequestHeader().getURI().toString(),
                is(equalTo("http://example.com/page1")));
        assertThat(get1.getRequestBody().toString(), is(equalTo("")));

        HttpMessage post = importedMessages.get(1);
        assertThat(post.getRequestHeader().getMethod(), is(equalTo("POST")));
        assertThat(
                post.getRequestHeader().getURI().toString(),
                is(equalTo("http://example.com/login")));
        assertThat(post.getRequestBody().toString(), is(equalTo("user=foo&pass=bar")));

        HttpMessage get2 = importedMessages.get(2);
        assertThat(get2.getRequestHeader().getMethod(), is(equalTo("GET")));
        assertThat(
                get2.getRequestHeader().getURI().toString(),
                is(equalTo("http://example.com/page2")));
    }

    private static void assertMessagesEqual(HttpMessage expected, HttpMessage actual) {
        assertThat(
                actual.getRequestHeader().getMethod(),
                is(equalTo(expected.getRequestHeader().getMethod())));
        assertThat(
                actual.getRequestHeader().getURI().toString(),
                is(equalTo(expected.getRequestHeader().getURI().toString())));
        assertThat(
                actual.getRequestBody().getBytes(),
                is(equalTo(expected.getRequestBody().getBytes())));
        assertThat(
                actual.getResponseHeader().getStatusCode(),
                is(equalTo(expected.getResponseHeader().getStatusCode())));
        assertThat(
                actual.getResponseBody().getBytes(),
                is(equalTo(expected.getResponseBody().getBytes())));
    }
}
