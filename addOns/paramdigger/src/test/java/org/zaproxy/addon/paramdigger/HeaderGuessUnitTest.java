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
package org.zaproxy.addon.paramdigger;

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.RETURNS_MOCKS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.withSettings;

import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.db.TableAlert;
import org.parosproxy.paros.db.TableHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.paramdigger.gui.ParamDiggerHistoryTableModel;
import org.zaproxy.zap.testutils.NanoServerHandler;
import org.zaproxy.zap.testutils.TestUtils;

class HeaderGuessUnitTest extends TestUtils {
    private HeaderGuesser headerGuesser;
    private GuesserScan scan;
    private TableHistory tableHistory;
    private ExecutorService executor;
    private ParamDiggerHistoryTableModel tableModel;
    private HttpSender httpSender = new HttpSender(HttpSender.PARAM_DIGGER_INITIATOR);
    private ParamDiggerConfig config;
    private static String TEST_WORDLIST_FILE = "wordlists/HeaderGuesserTestList.txt";
    private Path file;

    @BeforeEach
    void init() throws Exception {
        setUpZap();
        try (InputStream is =
                UrlGuesserUnitTest.class.getResourceAsStream("/" + TEST_WORDLIST_FILE)) {
            this.file = Paths.get(Constant.getZapHome(), TEST_WORDLIST_FILE);
            Files.createDirectories(file.getParent());
            Files.copy(is, file);
        }

        tableModel =
                mock(
                        ParamDiggerHistoryTableModel.class,
                        withSettings().defaultAnswer(RETURNS_MOCKS));
        tableHistory =
                mock(
                        TableHistory.class,
                        withSettings().defaultAnswer(RETURNS_MOCKS).strictness(Strictness.LENIENT));
        HistoryReference.setTableHistory(tableHistory);
        HistoryReference.setTableAlert(
                mock(
                        TableAlert.class,
                        withSettings()
                                .defaultAnswer(RETURNS_MOCKS)
                                .strictness(Strictness.LENIENT)));

        startServer();
        scan = mock(GuesserScan.class, withSettings().strictness(Strictness.LENIENT));
        given(scan.getTableModel()).willReturn(tableModel);
        executor = Executors.newFixedThreadPool(1);

        config = new ParamDiggerConfig();
        config.setUsePredefinedHeaderWordlists(false);
        config.setUseCustomHeaderWordlists(true);
        config.setCustomHeaderWordlistPath(file);
    }

    @AfterEach
    void tearDown() throws Exception {
        stopServer();
        executor.shutdown();
    }

    @Test
    void shouldGuessHostHeaderPoisoning() throws Exception {
        // Given
        String path = "/testHostBodyReflection";
        Map<String, String> params = new HashMap<>();
        Map<String, String> poisoning = new HashMap<>();
        this.nano.addHandler(
                new NanoServerHandler(path) {
                    int count = 0;

                    @Override
                    protected Response serve(IHTTPSession session) {
                        Map<String, List<String>> ps = session.getParameters();
                        String header = "x-cache";
                        String value = "miss";
                        for (Map.Entry<String, List<String>> entry : ps.entrySet()) {
                            if (params.containsKey(entry.getKey())
                                    && params.get(entry.getKey())
                                            .equalsIgnoreCase(entry.getValue().get(0))) {
                                value = "hit";
                            } else {
                                value = "miss";
                                params.put(entry.getKey(), entry.getValue().get(0));
                            }
                        }

                        /* This logic mimics caching in case no "URL parameter cache buster" is used. */
                        if (value.equals("miss") && count == 0 && ps.isEmpty()) {
                            count++;
                        } else if (ps.isEmpty()) {
                            value = "hit";
                        }

                        poisoning.put("host", session.getHeaders().get("host"));

                        Response response =
                                newFixedLengthResponse(
                                        getHtml(
                                                "AttributeName.html",
                                                new String[][] {
                                                    {
                                                        "q",
                                                        ((poisoning.get("host")) != null
                                                                        && value.equalsIgnoreCase(
                                                                                "hit"))
                                                                ? poisoning.get("host")
                                                                : ""
                                                    },
                                                    {
                                                        "p",
                                                        ((poisoning.get("host")) != null
                                                                        && value.equalsIgnoreCase(
                                                                                "hit"))
                                                                ? poisoning.get("host")
                                                                : ""
                                                    }
                                                }));
                        response.addHeader(header, value);
                        return response;
                    }
                });

        HttpMessage msg = getHttpMessage(path);
        config.setUrl(msg.getRequestHeader().getURI().toString());
        config.setHeaderGuessMethods(Method.GET);
        config.setDoHeaderGuess(true);
        given(scan.getConfig()).willReturn(config);
        headerGuesser = new HeaderGuesser(0, scan, httpSender, executor);

        // When
        headerGuesser.run();

        // Then
        ArgumentCaptor<ParamGuessResult> result = ArgumentCaptor.forClass(ParamGuessResult.class);
        verify(scan, times(14)).addParamGuessResult(result.capture());
        assertThat(
                result.getAllValues().get(0).getReasons(),
                contains(Reason.BODY_HEURISTIC_MISMATCH));
        assertThat(
                result.getAllValues().get(1).getReasons(),
                contains(Reason.BODY_HEURISTIC_MISMATCH));
        assertThat(
                result.getAllValues().get(2).getReasons(),
                contains(Reason.BODY_HEURISTIC_MISMATCH));
        assertThat(
                result.getAllValues().get(3).getReasons(),
                contains(Reason.BODY_HEURISTIC_MISMATCH));
    }

    @Test
    void shouldGuessHeadersForPoisonInResponseHeader() throws Exception {
        // Given
        String path = "/testHeaderReflection";
        Map<String, String> params = new HashMap<>();
        Map<String, String> poisoning = new HashMap<>();
        this.nano.addHandler(
                new NanoServerHandler(path) {
                    int count = 0;

                    @Override
                    protected Response serve(IHTTPSession session) {
                        Map<String, List<String>> ps = session.getParameters();
                        String header = "x-cache";
                        String value = "miss";
                        for (Map.Entry<String, List<String>> entry : ps.entrySet()) {
                            if (params.containsKey(entry.getKey())
                                    && params.get(entry.getKey())
                                            .equalsIgnoreCase(entry.getValue().get(0))) {
                                value = "hit";
                            } else {
                                value = "miss";
                                params.put(entry.getKey(), entry.getValue().get(0));
                            }
                        }

                        /* This logic mimics caching in case no "URL parameter cache buster" is used. */
                        if (value.equals("miss") && count == 0 && ps.isEmpty()) {
                            count++;
                        } else if (ps.isEmpty()) {
                            value = "hit";
                        }

                        String retVal = session.getHeaders().get("host");
                        if (retVal.contains(":31337")) {
                            poisoning.put("host", session.getHeaders().get("host"));
                        }

                        Response response = newFixedLengthResponse("OK");
                        response.addHeader(header, value);
                        if ((poisoning.get("host")) != null && value.equalsIgnoreCase("hit")) {
                            response.addHeader("Origin", poisoning.get("host"));
                        } else {
                            response.addHeader("Origin", session.getHeaders().get("host"));
                        }
                        return response;
                    }
                });

        HttpMessage msg = getHttpMessage(path);
        config.setUrl(msg.getRequestHeader().getURI().toString());
        config.setHeaderGuessMethods(Method.GET);
        config.setDoHeaderGuess(true);
        given(scan.getConfig()).willReturn(config);
        headerGuesser = new HeaderGuesser(0, scan, httpSender, executor);

        // When
        headerGuesser.run();

        // Then
        ArgumentCaptor<ParamGuessResult> result = ArgumentCaptor.forClass(ParamGuessResult.class);
        verify(scan, times(9)).addParamGuessResult(result.capture());
        assertThat(
                result.getAllValues().get(0).getReasons(),
                contains(Reason.POISON_REFLECTION_IN_HEADER));
        assertThat(
                result.getAllValues().get(1).getReasons(),
                contains(Reason.POISON_REFLECTION_IN_HEADER));
        assertThat(
                result.getAllValues().get(2).getReasons(),
                contains(Reason.POISON_REFLECTION_IN_HEADER));
    }

    @Test
    void shouldGuessHeadersForXForwardedHostPoisoning() throws HttpMalformedHeaderException {
        String path = "/testXForwardedHostHeaderReflection";
        Map<String, String> params = new HashMap<>();
        Map<String, String> poisoning = new HashMap<>();
        this.nano.addHandler(
                new NanoServerHandler(path) {
                    int count = 0;

                    @Override
                    protected Response serve(IHTTPSession session) {
                        Map<String, List<String>> ps = session.getParameters();
                        String header = "x-cache";
                        String value = "miss";
                        for (Map.Entry<String, List<String>> entry : ps.entrySet()) {
                            if (params.containsKey(entry.getKey())
                                    && params.get(entry.getKey())
                                            .equalsIgnoreCase(entry.getValue().get(0))) {
                                value = "hit";
                            } else {
                                value = "miss";
                                params.put(entry.getKey(), entry.getValue().get(0));
                            }
                        }

                        if (value.equals("miss") && count == 0 && ps.isEmpty()) {
                            count++;
                        } else if (ps.isEmpty()) {
                            value = "hit";
                        }

                        String retVal = session.getHeaders().get("x-forwarded-host");
                        if (retVal != null
                                && !retVal.isEmpty()
                                && session.getHeaders()
                                        .get("x-forwarded-scheme")
                                        .equalsIgnoreCase("nothttps")) {
                            poisoning.put("x-forwarded-host", retVal);
                        }

                        Response response =
                                newFixedLengthResponse(
                                        getHtml(
                                                "AttributeValue.html",
                                                new String[][] {
                                                    {"q", "src"},
                                                    {
                                                        "p",
                                                        (poisoning.get("x-forwarded-host")) != null
                                                                ? poisoning.get("x-forwarded-host")
                                                                : "localhost"
                                                    }
                                                }));
                        response.addHeader(header, value);
                        return response;
                    }
                });

        HttpMessage msg = getHttpMessage(path);
        config.setUrl(msg.getRequestHeader().getURI().toString());
        config.setHeaderGuessMethods(Method.GET);
        config.setDoHeaderGuess(true);
        given(scan.getConfig()).willReturn(config);
        headerGuesser = new HeaderGuesser(0, scan, httpSender, executor);

        // When
        headerGuesser.run();

        // Then
        ArgumentCaptor<ParamGuessResult> result = ArgumentCaptor.forClass(ParamGuessResult.class);
        verify(scan, times(2)).addParamGuessResult(result.capture());
        assertThat(
                result.getAllValues().get(0).getReasons(),
                contains(Reason.POISON_REFLECTION_IN_BODY));
        assertThat(
                result.getAllValues().get(1).getReasons(),
                contains(Reason.POISON_REFLECTION_IN_BODY));
    }

    @Test
    void shouldGuessHeadersForForwardedPortPoisoning() throws HttpMalformedHeaderException {
        String path = "/testForwardedPortHeaderReflection";
        Map<String, String> params = new HashMap<>();
        Map<String, String> poisoning = new HashMap<>();
        this.nano.addHandler(
                new NanoServerHandler(path) {
                    int count = 0;

                    @Override
                    protected Response serve(IHTTPSession session) {
                        Map<String, List<String>> ps = session.getParameters();
                        String header = "x-cache";
                        String value = "miss";
                        for (Map.Entry<String, List<String>> entry : ps.entrySet()) {
                            if (params.containsKey(entry.getKey())
                                    && params.get(entry.getKey())
                                            .equalsIgnoreCase(entry.getValue().get(0))) {
                                value = "hit";
                            } else {
                                value = "miss";
                                params.put(entry.getKey(), entry.getValue().get(0));
                            }
                        }

                        if (value.equals("miss") && count == 0 && ps.isEmpty()) {
                            count++;
                        } else if (ps.isEmpty()) {
                            value = "hit";
                        }

                        String retVal = session.getHeaders().get("x-forwarded-port");
                        if (retVal != null && !retVal.isEmpty()) {
                            poisoning.put("forwarded", retVal);
                        }

                        Response response = newFixedLengthResponse("OK");
                        response.addHeader(header, value);
                        response.addHeader(
                                "forwarded",
                                ((poisoning.get("forwarded")) != null)
                                        ? poisoning.get("forwarded")
                                        : "localhost");
                        return response;
                    }
                });

        HttpMessage msg = getHttpMessage(path);
        config.setUrl(msg.getRequestHeader().getURI().toString());
        config.setHeaderGuessMethods(Method.GET);
        config.setDoHeaderGuess(true);
        given(scan.getConfig()).willReturn(config);
        headerGuesser = new HeaderGuesser(0, scan, httpSender, executor);

        // When
        headerGuesser.run();

        // Then
        ArgumentCaptor<ParamGuessResult> result = ArgumentCaptor.forClass(ParamGuessResult.class);
        verify(scan, times(3)).addParamGuessResult(result.capture());
        assertThat(
                result.getAllValues().get(0).getReasons(),
                contains(Reason.POISON_REFLECTION_IN_HEADER));
    }
}
