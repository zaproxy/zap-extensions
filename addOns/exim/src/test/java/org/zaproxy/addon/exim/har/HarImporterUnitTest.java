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
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.withSettings;

import de.sstoehr.harreader.HarReader;
import de.sstoehr.harreader.HarReaderException;
import de.sstoehr.harreader.model.HarEntry;
import de.sstoehr.harreader.model.HarLog;
import de.sstoehr.harreader.model.HarLog.HarLogBuilder;
import fi.iki.elonen.NanoHTTPD;
import java.io.File;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
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
import org.parosproxy.paros.control.Control.Mode;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.db.RecordHistory;
import org.parosproxy.paros.db.TableAlert;
import org.parosproxy.paros.db.TableHistory;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.extension.option.OptionsParamView;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.model.SiteMap;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.commonlib.ui.ProgressPaneListener;
import org.zaproxy.addon.exim.ExtensionExim;
import org.zaproxy.zap.testutils.NanoServerHandler;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.Stats;
import org.zaproxy.zap.utils.StatsListener;

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
    private StatsListener statsListener;

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

        OptionsParam optionsParam =
                mock(OptionsParam.class, withSettings().strictness(Strictness.LENIENT));
        OptionsParamView viewParam =
                mock(OptionsParamView.class, withSettings().strictness(Strictness.LENIENT));
        given(model.getOptionsParam()).willReturn(optionsParam);
        given(optionsParam.getViewParam()).willReturn(viewParam);
        given(viewParam.getMode()).willReturn(Mode.standard.name());

        extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        extHistory = mock(ExtensionHistory.class);
        given(extensionLoader.getExtension(ExtensionHistory.class)).willReturn(extHistory);
        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);

        siteMap = mock(SiteMap.class);
        given(session.getSiteTree()).willReturn(siteMap);
    }

    @BeforeEach
    void beforeEach() {
        statsListener = mock();
        Stats.addListener(statsListener);
        given(session.isInScope(anyString())).willReturn(true);

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
        Stats.removeListener(statsListener);
        stopServer();
        Control.getSingleton().setMode(Mode.standard);

        Configurator.reconfigure(getClass().getResource("/log4j2-test.properties").toURI());
    }

    @Test
    void serializedAndDeserializedShouldMatch() throws Exception {
        // Given
        var requestHeader =
                "POST http://example.com/path HTTP/1.1\r\nContent-Type: application/octet-stream\r\n\r\n";
        var responseHeader = "HTTP/1.1 200 OK\r\nContent-Type: text/plain;charset=US-ASCII\r\n\r\n";
        byte[] requestBody = {0x01, 0x02};
        byte[] responseBody = {0x30, 0x31};
        HttpMessage httpMessage =
                new HttpMessage(requestHeader, requestBody, responseHeader, responseBody);
        long timeSentMillis = 1234L;
        httpMessage.setTimeSentMillis(timeSentMillis);
        int timeElapsedMillis = 42;
        httpMessage.setTimeElapsedMillis(timeElapsedMillis);

        HarLog harLog = createHarLog(httpMessage);
        // When
        List<HttpMessage> deserialized = HarImporter.getHttpMessages(harLog);
        // Then
        assertThat(deserialized, hasSize(1));
        var deserializedHttpMessage = deserialized.get(0);
        assertThat(
                deserializedHttpMessage.getRequestHeader().toString(), is(equalTo(requestHeader)));
        assertThat(deserializedHttpMessage.getRequestBody().getBytes(), is(equalTo(requestBody)));
        assertThat(
                deserializedHttpMessage.getResponseHeader().toString(),
                is(equalTo(responseHeader)));
        assertThat(deserializedHttpMessage.getResponseBody().getBytes(), is(equalTo(responseBody)));
        assertThat(deserializedHttpMessage.getTimeSentMillis(), is(equalTo(timeSentMillis)));
        assertThat(deserializedHttpMessage.getTimeElapsedMillis(), is(equalTo(timeElapsedMillis)));
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
        verify(statsListener).counterInc("stats.exim.import.har.file.errors");
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
        verify(statsListener).counterInc("stats.exim.import.har.file");
        verify(statsListener).counterInc("stats.exim.import.har.file.message");
    }

    @Test
    void shouldImportHarFromString() throws Exception {
        // Given / When
        HarImporter importer = new HarImporter(Files.readString(getResourcePath("noresponse.har")));
        // Then
        assertThat(importer.isSuccess(), equalTo(true));
        verify(statsListener).counterInc("stats.exim.import.har.string");
        verify(statsListener).counterInc("stats.exim.import.har.string.message");
    }

    @Test
    void shouldSendRequestsWhenSendRequestsEnabled() throws Exception {
        // Given
        startServer();
        AtomicBoolean hit = new AtomicBoolean();
        nano.addHandler(hitHandler(hit));
        ProgressPaneListener listener = mock(ProgressPaneListener.class);
        // When
        HarImporter importer =
                new HarImporter(createHarLog(createLiveMessage("/")), listener, true);
        // Then
        assertThat(importer.isSuccess(), equalTo(true));
        assertThat(hit.get(), equalTo(true));
        verify(listener).completed();
        verify(statsListener).counterInc("stats.exim.import.har.file.message");
    }

    @Test
    void shouldNotSendRequestsInSafeMode() throws Exception {
        // Given
        Control.getSingleton().setMode(Mode.safe);
        startServer();
        AtomicBoolean hit = new AtomicBoolean();
        nano.addHandler(hitHandler(hit));
        // When
        HarImporter importer = new HarImporter(createHarLog(createLiveMessage("/")), null, true);
        // Then
        assertThat(importer.isSuccess(), equalTo(true));
        assertThat(hit.get(), equalTo(false));
        verify(statsListener, never()).counterInc("stats.exim.import.har.file.message");
    }

    @Test
    void shouldNotSendOutOfScopeRequestsInProtectMode() throws Exception {
        // Given
        Control.getSingleton().setMode(Mode.protect);
        given(session.isInScope(anyString())).willReturn(false);
        startServer();
        AtomicBoolean hit = new AtomicBoolean();
        nano.addHandler(hitHandler(hit));
        // When
        HarImporter importer = new HarImporter(createHarLog(createLiveMessage("/")), null, true);
        // Then
        assertThat(importer.isSuccess(), equalTo(true));
        assertThat(hit.get(), equalTo(false));
        verify(statsListener, never()).counterInc("stats.exim.import.har.file.message");
    }

    @Test
    void shouldNotFollowOutOfScopeRedirectInProtectMode() throws Exception {
        // Given
        Control.getSingleton().setMode(Mode.protect);
        startServer();
        String localUrl = "http://127.0.0.1:" + nano.getListeningPort() + "/";
        given(session.isInScope(localUrl)).willReturn(true);
        given(session.isInScope(argThat((String u) -> u != null && u.contains("example.org"))))
                .willReturn(false);
        AtomicBoolean redirected = new AtomicBoolean();
        nano.addHandler(
                new NanoServerHandler("/") {
                    @Override
                    protected NanoHTTPD.Response serve(NanoHTTPD.IHTTPSession session) {
                        if ("/final".equals(session.getUri())) {
                            redirected.set(true);
                            return NanoHTTPD.newFixedLengthResponse("final");
                        }
                        NanoHTTPD.Response response =
                                NanoHTTPD.newFixedLengthResponse(
                                        NanoHTTPD.Response.Status.REDIRECT,
                                        NanoHTTPD.MIME_PLAINTEXT,
                                        "");
                        response.addHeader("Location", "http://example.org/out");
                        return response;
                    }
                });
        // When
        HarImporter importer = new HarImporter(createHarLog(createLiveMessage("/")), null, true);
        // Then
        assertThat(importer.isSuccess(), equalTo(true));
        assertThat(redirected.get(), equalTo(false));
    }

    @Test
    void shouldSkipMalformedRequestWhenSendRequestsEnabled() throws Exception {
        // Given
        String har =
                Files.readString(getResourcePath("noresponse.har"))
                        .replace("\"url\": \"http://example.com/\"", "\"url\": \"\"");
        // When
        HarImporter importer = new HarImporter(har, true);
        // Then
        assertThat(importer.isSuccess(), equalTo(true));
        verify(statsListener, never()).counterInc("stats.exim.import.har.string.message");
        assertThat(
                logMessages.stream().map(String::trim).toList(),
                hasItem(
                        equalTo(
                                "Failed to send HAR request: Failed to find pattern (\\w+) +([^\\r\\n]+) +(HTTP/\\d+(?:\\.\\d+)?) in: GET  HTTP/1.1")));
    }

    @Test
    void shouldNotImportNonHarFromString() {
        // Given / When
        HarImporter importer = new HarImporter("Not HAR");
        // Then
        assertThat(importer.isSuccess(), equalTo(false));
        verify(statsListener).counterInc("stats.exim.import.har.string.errors");
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

    private HttpMessage createLiveMessage(String path) throws HttpMalformedHeaderException {
        String url = "http://127.0.0.1:" + nano.getListeningPort() + path;
        return new HttpMessage(
                "GET " + url + " HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
                EMPTY_BODY,
                "HTTP/1.1 200 OK\r\n\r\n",
                "recorded".getBytes(StandardCharsets.US_ASCII));
    }

    private static NanoServerHandler hitHandler(AtomicBoolean hit) {
        return new NanoServerHandler("/") {
            @Override
            protected NanoHTTPD.Response serve(NanoHTTPD.IHTTPSession session) {
                hit.set(true);
                return NanoHTTPD.newFixedLengthResponse("live-body");
            }
        };
    }

    private HarLog getHarLog(String path, String replacement) throws HarReaderException {
        return new HarReader()
                .readFromString(getHtml(path, Map.of(PLACEHOLDER, replacement)))
                .log();
    }

    private static HarLog createHarLog(HttpMessage message) {
        HarLogBuilder harLog = HarUtils.createZapHarLog();
        List<HarEntry> harEntries = new ArrayList<>();
        harEntries.add(HarUtils.createHarEntry(message));
        harLog.entries(harEntries);
        return harLog.build();
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
