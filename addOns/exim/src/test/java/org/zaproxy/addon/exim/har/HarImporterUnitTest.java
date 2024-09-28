/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
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
package org.zaproxy.addon.exim.har;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.emptyString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.withSettings;

import de.sstoehr.harreader.HarReader;
import de.sstoehr.harreader.HarReaderException;
import de.sstoehr.harreader.model.HarEntry;
import de.sstoehr.harreader.model.HarLog;
import java.io.File;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.StringLayout;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.config.Configurator;
import org.apache.logging.log4j.core.config.LoggerConfig;
import org.apache.logging.log4j.core.config.Property;
import org.apache.logging.log4j.core.filter.BurstFilter;
import org.apache.logging.log4j.core.layout.PatternLayout;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.db.RecordHistory;
import org.parosproxy.paros.db.TableAlert;
import org.parosproxy.paros.db.TableHistory;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.model.SiteMap;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.commonlib.ui.ProgressPaneListener;
import org.zaproxy.addon.exim.ExtensionExim;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit test for {@link HarImporter}. */
class HarImporterUnitTest extends TestUtils {

    private static final String APPENDER_NAME = "ZAP-TestAppender";
    private static final byte[] EMPTY_BODY = {};
    private static final String PLACEHOLDER = "replace";
    private static final String DEFAULT_RESPONSE_HEADER =
            "HTTP/1.0 0" + HttpHeader.CRLF + HttpHeader.CRLF;

    private static TableHistory tableHistory;
    private static long sessionId;
    private static Session session;
    private static ExtensionLoader extensionLoader;
    private static ExtensionHistory extHistory;
    private static SiteMap siteMap;

    private List<String> logMessages;

    @BeforeAll
    static void setup() throws HttpMalformedHeaderException, DatabaseException {
        mockMessages(new ExtensionExim());

        tableHistory = mock(TableHistory.class, withSettings().strictness(Strictness.LENIENT));
        given(tableHistory.write(anyLong(), anyInt(), any())).willReturn(mock(RecordHistory.class));
        HistoryReference.setTableHistory(tableHistory);
        HistoryReference.setTableAlert(mock(TableAlert.class));

        Model model = mock(Model.class, withSettings().strictness(Strictness.LENIENT));
        Model.setSingletonForTesting(model);
        session = mock(Session.class, withSettings().strictness(Strictness.LENIENT));
        given(model.getSession()).willReturn(session);
        sessionId = 1234;
        given(session.getSessionId()).willReturn(sessionId);

        extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        extHistory = mock(ExtensionHistory.class);
        given(extensionLoader.getExtension(ExtensionHistory.class)).willReturn(extHistory);
        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);

        siteMap = mock(SiteMap.class);
        given(session.getSiteTree()).willReturn(siteMap);
    }

    @BeforeEach
    void initLogger() {
        logMessages = new ArrayList<>();
        LoggerConfig rootLogger = LoggerContext.getContext().getConfiguration().getRootLogger();
        rootLogger.addAppender(new TestAppender(logMessages::add), null, null);
        Configurator.setRootLevel(Level.ALL);
    }

    @AfterAll
    static void cleanup() {
        Constant.messages = null;
        HistoryReference.setTableHistory(null);
        HistoryReference.setTableAlert(null);
    }

    @AfterEach
    void reset() throws URISyntaxException {
        Configurator.reconfigure(getClass().getResource("/log4j2-test.properties").toURI());
    }

    @Test
    void serializedAndDeserializedShouldMatch() throws Exception {
        // Given
        byte[] requestBody = {0x01, 0x02};
        byte[] responseBody = {0x30, 0x31};
        HttpMessage httpMessage =
                new HttpMessage(
                        "POST /path HTTP/1.1\r\nContent-Type: application/octet-stream\r\n\r\n",
                        requestBody,
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain;charset=US-ASCII\r\n\r\n",
                        responseBody);

        HarLog harLog = createHarLog(httpMessage);
        // When
        List<HttpMessage> deserialized = HarImporter.getHttpMessages(harLog);
        // Then
        assertThat(deserialized, hasSize(1));
        assertThat(deserialized.get(0), equalTo(httpMessage));
    }

    @Test
    void shouldHaveValidResponseSetFromTargetHost() throws Exception {
        // Given
        HarLog harLog =
                createHarLog(
                        new HttpMessage(
                                "GET / HTTP/1.1", EMPTY_BODY, "HTTP/1.1 200 OK", EMPTY_BODY));
        // When
        List<HttpMessage> messages = HarImporter.getHttpMessages(harLog);
        // Then
        assertThat(messages, hasSize(1));
        assertThat(messages.get(0).isResponseFromTargetHost(), equalTo(true));
    }

    @Test
    void shouldHaveInvalidResponseNotSetFromTargetHost() throws Exception {
        // Given
        HarLog harLog = createHarLog(new HttpMessage(new HttpRequestHeader("GET / HTTP/1.1")));
        // When
        List<HttpMessage> messages = HarImporter.getHttpMessages(harLog);
        // Then
        assertThat(messages, hasSize(1));
        assertThat(messages.get(0).isResponseFromTargetHost(), equalTo(false));
    }

    @Test
    void shouldBeFailureIfFileNotFound(@TempDir Path dir) throws Exception {
        // Given
        File file = dir.resolve("missing.har").toFile();
        // When
        HarImporter importer = new HarImporter(file);
        // Then
        assertThat(importer.isSuccess(), equalTo(false));
    }

    @Test
    void shouldCompleteListenerIfFileNotFound(@TempDir Path dir) throws Exception {
        // Given
        File file = dir.resolve("missing.har").toFile();
        ProgressPaneListener listener = mock(ProgressPaneListener.class);
        // When
        HarImporter importer = new HarImporter(file, listener);
        // Then
        assertThat(importer.isSuccess(), equalTo(false));
        verify(listener).completed();
    }

    @Test
    void shouldImportIfHarEntryHasNoResponse() throws Exception {
        // Given
        ProgressPaneListener listener = mock(ProgressPaneListener.class);
        // When
        HarImporter importer =
                new HarImporter(getResourcePath("noresponse.har").toFile(), listener);
        // Then
        assertThat(importer.isSuccess(), equalTo(true));
        verify(listener).completed();
    }

    @Test
    void shouldCountNullMessagesTowardsTasksDone() {
        // Given
        ProgressPaneListener listener = mock(ProgressPaneListener.class);
        // When
        new HarImporter(getResourcePath("oneNullMessage.har").toFile(), listener);
        // Then
        verify(listener).setTasksDone(1);
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "templates/replaceableReqHttpVer.har",
                "templates/replaceableRespHttpVer.har"
            })
    void shouldSkipEntryIfHttpVersionInvalid(String templateFile) throws Exception {
        // Given
        HarLog harLog = getHarLog(templateFile, "Foo");
        // When
        HarImporter.getHttpMessages(harLog);
        // Then
        assertTrue(logMessages.get(0).startsWith("Message with unsupported HTTP version"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", HttpHeader.HTTP})
    void shouldSetReqHttpVersionWhenMissing(String version) throws Exception {
        // Given
        HarLog harLog = getHarLog("templates/replaceableReqHttpVer.har", version);
        // When
        List<HttpMessage> messages = HarImporter.getHttpMessages(harLog);
        // Then
        assertThat(messages, hasSize(1));
        HttpMessage processed = messages.get(0);
        assertThat(processed.getRequestHeader().getVersion(), is(equalTo(HttpHeader.HTTP11)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", HttpHeader.HTTP})
    void shouldSetRespHttpVersionWhenMissing(String version) throws Exception {
        // Given
        HarLog harLog = getHarLog("templates/replaceableRespHttpVer.har", version);
        // When
        List<HttpMessage> messages = HarImporter.getHttpMessages(harLog);
        // Then
        assertThat(messages, hasSize(1));
        HttpMessage processed = messages.get(0);
        assertThat(processed.getResponseHeader().getVersion(), is(equalTo(HttpHeader.HTTP11)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"h3", "http/3", "http/3.0"})
    void shouldSetHttp2ReqIfHttpVersionHttp3(String version) throws Exception {
        // Given
        HarLog harLog = getHarLog("templates/replaceableReqHttpVer.har", version);
        // When
        List<HttpMessage> messages = HarImporter.getHttpMessages(harLog);
        // Then
        assertThat(messages, hasSize(1));
        HttpMessage processed = messages.get(0);
        assertThat(processed.getRequestHeader().getVersion(), is(equalTo(HttpHeader.HTTP2)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"h3", "http/3", "http/3.0"})
    void shouldSetHttp2RespIfHttpVersionHttp3(String version) throws Exception {
        // Given
        HarLog harLog = getHarLog("templates/replaceableRespHttpVer.har", version);
        // When
        List<HttpMessage> messages = HarImporter.getHttpMessages(harLog);
        // Then
        assertThat(messages, hasSize(1));
        HttpMessage processed = messages.get(0);
        assertThat(processed.getResponseHeader().getVersion(), is(equalTo(HttpHeader.HTTP2)));
    }

    @Test
    void shouldHandleSetCookiesWithLFAndUsableHeader() throws Exception {
        // Given
        HarLog harLog = getHarLog("cookiesLFWithUsableResponseHeader.har", "");
        // When
        List<HttpMessage> messages = HarImporter.getHttpMessages(harLog);
        // Then
        assertThat(messages, hasSize(1));
        HttpMessage processed = messages.get(0);
        assertThat(processed.getResponseHeader().toString(), is(not(emptyString())));
        assertThat(logMessages, hasSize(1));
    }

    @Test
    void shouldHandleSetCookiesWithLFAndUnusableHeader() throws Exception {
        // Given
        HarLog harLog = getHarLog("cookiesLFWithUnusableResponseHeader.har", "");
        // When
        List<HttpMessage> messages = HarImporter.getHttpMessages(harLog);
        // Then
        assertThat(messages, hasSize(1));
        HttpMessage processed = messages.get(0);
        assertThat(processed.getResponseHeader().toString(), is(equalTo(DEFAULT_RESPONSE_HEADER)));
        assertThat(logMessages, hasSize(2));
    }

    @Test
    void shouldSkipLocalPrivate() throws Exception {
        // Given
        HarLog harLog = getHarLog("localPrivateAboutBlank.har", "");
        // When
        List<HttpMessage> messages = HarImporter.getHttpMessages(harLog);
        // Then
        assertThat(messages, hasSize(0));
        assertThat(logMessages, hasSize(1));
        assertThat(
                logMessages.get(0).trim(),
                is(equalTo("Skipping local private entry: about:blank")));
    }

    @Test
    void shouldBase64DecodeResponseBody() throws Exception {
        // Given
        HarLog harLog = getHarLog("response-base64.har", "");
        // When
        List<HttpMessage> messages = HarImporter.getHttpMessages(harLog);
        // Then
        assertThat(messages, hasSize(1));
        assertThat(messages.get(0).getResponseBody().toString(), is(equalTo("1234")));
    }

    @Test
    void shouldFallbackToPlainTextOnMalformedBase64ResponseBody() throws Exception {
        // Given
        HarLog harLog = getHarLog("response-base64-invalid.har", "");
        // When
        List<HttpMessage> messages = HarImporter.getHttpMessages(harLog);
        // Then
        assertThat(messages, hasSize(1));
        assertThat(messages.get(0).getResponseBody().toString(), is(equalTo("Not base 64")));
    }

    private HarLog getHarLog(String path, String replacement) throws HarReaderException {
        return new HarReader()
                .readFromString(getHtml(path, Map.of(PLACEHOLDER, replacement)))
                .getLog();
    }

    private static HarLog createHarLog(HttpMessage message) {
        HarLog harLog = HarUtils.createZapHarLog();
        List<HarEntry> harEntries = new ArrayList<>();
        harEntries.add(HarUtils.createHarEntry(message));
        harLog.setEntries(harEntries);
        return harLog;
    }

    static class TestAppender extends AbstractAppender {

        private static final Property[] NO_PROPERTIES = {};

        private final Consumer<String> logConsumer;

        TestAppender(Consumer<String> logConsumer) {
            super(
                    APPENDER_NAME,
                    BurstFilter.newBuilder().setMaxBurst(100).setLevel(Level.WARN).build(),
                    PatternLayout.newBuilder()
                            .withDisableAnsi(true)
                            .withCharset(StandardCharsets.UTF_8)
                            .withPattern("%m%n")
                            .build(),
                    true,
                    NO_PROPERTIES);
            this.logConsumer = logConsumer;
            start();
        }

        @Override
        public void append(LogEvent event) {
            logConsumer.accept(((StringLayout) getLayout()).toSerializable(event));
        }
    }
}
