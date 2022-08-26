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
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.RETURNS_MOCKS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.withSettings;

import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.db.TableAlert;
import org.parosproxy.paros.db.TableHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.paramdigger.ParamGuessResult.Reason;
import org.zaproxy.addon.paramdigger.gui.ParamDiggerHistoryTableModel;
import org.zaproxy.zap.testutils.NanoServerHandler;
import org.zaproxy.zap.testutils.TestUtils;

public class UrlGuesserUnitTest extends TestUtils {
    private UrlGuesser urlGuesser;
    private GuesserScan scan;
    private ExecutorService executor;
    private TableHistory tableHistory;
    private ParamDiggerHistoryTableModel tableModel;
    private HttpSender httpSender =
            new HttpSender(Model.getSingleton().getOptionsParam().getConnectionParam(), true, 17);
    private ParamDiggerConfig config;
    private static String TEST_WORDLIST_FILE = "wordlists/UrlGuesserTestList.txt";
    private Path file;

    private static String htmlEscape(String value) {
        return value.replace("<", "&lt;").replace(">", "&gt;").replace("&", "&amp;");
    }

    private static String encodeUrl(String value) {
        try {
            return URLEncoder.encode(value, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            return null;
        }
    }

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
                mock(TableHistory.class, withSettings().defaultAnswer(RETURNS_MOCKS).lenient());
        HistoryReference.setTableHistory(tableHistory);
        HistoryReference.setTableAlert(
                mock(TableAlert.class, withSettings().defaultAnswer(RETURNS_MOCKS).lenient()));

        startServer();
        scan = mock(GuesserScan.class, withSettings().lenient());
        given(scan.getTableModel()).willReturn(tableModel);
        executor = Executors.newFixedThreadPool(1);

        config = new ParamDiggerConfig();
        config.setUsePredefinedUrlWordlists(false);
        config.setUseCustomUrlWordlists(true);
        config.setCustomUrlWordlistPath(file);
    }

    @AfterEach
    void tearDown() throws Exception {
        stopServer();
        executor.shutdown();
    }

    @Test
    void shouldGuessUrlParametersWithoutErrors() throws Exception {
        // Given
        String path = "/body";
        this.nano.addHandler(
                new NanoServerHandler(path) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String name = getFirstParamValue(session, "q");
                        name = name == null ? " " : name;
                        String response =
                                getHtml("ReflectionInBody.html", new String[][] {{"q", name}});

                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = getHttpMessage(path);
        config.setUrl(msg.getRequestHeader().getURI().toString());
        config.setDoUrlGuess(true);
        config.setUrlGetRequest(true);
        given(scan.getConfig()).willReturn(config);
        urlGuesser = new UrlGuesser(0, scan, httpSender, executor);

        // When
        urlGuesser.run();

        // Then
        ArgumentCaptor<ParamGuessResult> result = ArgumentCaptor.forClass(ParamGuessResult.class);
        verify(scan).addParamGuessResult(result.capture());
        assertThat(result.getValue().getParamName(), equalTo("q"));
        assertThat(
                result.getValue().getReasons(),
                contains(
                        Reason.HTTP_HEADERS,
                        Reason.WORD_COUNT,
                        Reason.TEXT,
                        Reason.PARAM_VALUE_REFLECTION));
    }

    @Test
    void shouldGuessParamteresForReflectionInTags() throws Exception {
        // Given
        String path = "/tag";
        this.nano.addHandler(
                new NanoServerHandler(path) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String name = getFirstParamValue(session, "q");
                        name = name == null ? " " : name;
                        String response =
                                getHtml("ReflectionInTag.html", new String[][] {{"q", name}});

                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = getHttpMessage(path);
        config.setUrl(msg.getRequestHeader().getURI().toString());
        config.setDoUrlGuess(true);
        config.setUrlGetRequest(true);
        given(scan.getConfig()).willReturn(config);
        urlGuesser = new UrlGuesser(0, scan, httpSender, executor);

        // When
        urlGuesser.run();

        // Then
        ArgumentCaptor<ParamGuessResult> result = ArgumentCaptor.forClass(ParamGuessResult.class);
        verify(scan).addParamGuessResult(result.capture());
        assertThat(result.getValue().getParamName(), equalTo("q"));
        assertThat(
                result.getValue().getReasons(),
                contains(Reason.HTTP_HEADERS, Reason.WORD_COUNT, Reason.TEXT));
    }

    @Test
    void shouldGuessParametersForJsonResponses() throws Exception {
        // Given
        String path = "/json";
        this.nano.addHandler(
                new NanoServerHandler(path) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String parameters = getBody(session);
                        parameters = parameters == null ? " " : parameters;
                        String response;
                        if (parameters.contains("q")) {
                            response = "{\"q\":true}";
                        } else {
                            response = "{}";
                        }
                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = getHttpMessage(path);
        config.setUrl(msg.getRequestHeader().getURI().toString());
        config.setDoUrlGuess(true);
        config.setUrlJsonRequest(true);
        given(scan.getConfig()).willReturn(config);
        urlGuesser = new UrlGuesser(0, scan, httpSender, executor);

        // When
        urlGuesser.run();

        // Then
        ArgumentCaptor<ParamGuessResult> result = ArgumentCaptor.forClass(ParamGuessResult.class);
        verify(scan).addParamGuessResult(result.capture());
        assertThat(result.getValue().getParamName(), equalTo("q"));
        assertThat(result.getValue().getReasons().get(1), equalTo(Reason.TEXT));
        assertThat(result.getValue().getReasons().get(0), equalTo(Reason.HTTP_HEADERS));
    }

    @Test
    void shouldGuessParametersForPostRequest() throws Exception {
        // Given
        String path = "/post";
        this.nano.addHandler(
                new NanoServerHandler(path) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String parameters = getBody(session);
                        parameters = parameters == null ? " " : parameters;
                        String response;
                        if (parameters.contains("q")) {
                            String value;
                            if (parameters.contains("&")) {
                                value =
                                        parameters.substring(
                                                parameters.indexOf("q"),
                                                parameters.indexOf('&', parameters.indexOf("q")));
                            } else {
                                value = parameters.substring(parameters.indexOf("q"));
                            }
                            response = "{\"q\":" + value + "}";
                        } else {
                            response = "{}";
                        }
                        return newFixedLengthResponse(response);
                    }
                });
        HttpMessage msg = getHttpMessage(path);
        config.setUrl(msg.getRequestHeader().getURI().toString());
        config.setDoUrlGuess(true);
        config.setUrlPostRequest(true);
        given(scan.getConfig()).willReturn(config);
        urlGuesser = new UrlGuesser(0, scan, httpSender, executor);

        // When
        urlGuesser.run();

        // Then
        ArgumentCaptor<ParamGuessResult> result = ArgumentCaptor.forClass(ParamGuessResult.class);
        verify(scan).addParamGuessResult(result.capture());
        assertThat(result.getValue().getParamName(), equalTo("q"));
        assertThat(result.getValue().getReasons(), contains(Reason.HTTP_HEADERS, Reason.TEXT));
    }

    @Test
    void shouldGuessParamsForXmlResponses() throws Exception {
        // Given
        String path = "/xml";
        this.nano.addHandler(
                new NanoServerHandler(path) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String parameters = getBody(session);
                        parameters = parameters == null ? " " : parameters;
                        String response;
                        if (parameters.contains("q")) {
                            response = "<q>true</q>";
                        } else {
                            response = "<q></q>";
                        }
                        return newFixedLengthResponse(response);
                    }
                });
        HttpMessage msg = getHttpMessage(path);
        config.setUrl(msg.getRequestHeader().getURI().toString());
        config.setDoUrlGuess(true);
        config.setUrlXmlRequest(true);
        String xmlIncludeString =
                "<?xml version=\"1.0\" encoding=\"utf-8\"?> <resources> $ZAP$</resources>";
        config.setUrlXmlIncludeString(xmlIncludeString);
        given(scan.getConfig()).willReturn(config);
        urlGuesser = new UrlGuesser(0, scan, httpSender, executor);

        // When
        urlGuesser.run();

        // Then
        ArgumentCaptor<ParamGuessResult> result = ArgumentCaptor.forClass(ParamGuessResult.class);
        verify(scan).addParamGuessResult(result.capture());
        assertThat(result.getValue().getParamName(), equalTo("q"));
        assertThat(result.getValue().getReasons(), contains(Reason.HTTP_HEADERS, Reason.TEXT));
    }

    @Test
    void shouldGuessParamsForHtmlEncoding() throws Exception {
        String test = "/test";

        this.nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String q = getFirstParamValue(session, "q");
                        String p = getFirstParamValue(session, "access");
                        if (q == null) {
                            q = "";
                        } else {
                            p = "";
                        }
                        String response;
                        q = htmlEscape(q);
                        p = htmlEscape(p);
                        response =
                                getHtml("AttributeName.html", new String[][] {{"q", q}, {"p", p}});
                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = this.getHttpMessage(test);
        config.setUrl(msg.getRequestHeader().getURI().toString());
        config.setDoUrlGuess(true);
        config.setUrlGetRequest(true);
        given(scan.getConfig()).willReturn(config);
        urlGuesser = new UrlGuesser(0, scan, httpSender, executor);

        // When
        urlGuesser.run();

        // Then
        ArgumentCaptor<ParamGuessResult> result = ArgumentCaptor.forClass(ParamGuessResult.class);
        verify(scan, times(2)).addParamGuessResult(result.capture());
        assertThat(result.getAllValues(), hasSize(2));
        assertThat(result.getAllValues().get(0).getParamName(), equalTo("q"));
        assertThat(
                result.getAllValues().get(0).getReasons(),
                contains(
                        Reason.HTTP_CODE,
                        Reason.HTTP_HEADERS,
                        Reason.BODY_HEURISTIC_MISMATCH,
                        Reason.LINE_COUNT,
                        Reason.WORD_COUNT,
                        Reason.TEXT));

        assertThat(result.getAllValues().get(1).getParamName(), equalTo("access"));
        assertThat(
                result.getAllValues().get(1).getReasons(),
                contains(
                        Reason.HTTP_CODE,
                        Reason.HTTP_HEADERS,
                        Reason.BODY_HEURISTIC_MISMATCH,
                        Reason.LINE_COUNT,
                        Reason.WORD_COUNT,
                        Reason.TEXT));
    }

    @Test
    void shouldGuessParamsForServerSideUrlEncoding() throws Exception {
        String test = "/test";

        this.nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String q = getFirstParamValue(session, "q");
                        String p = getFirstParamValue(session, "access");
                        q = q == null ? "" : q;
                        p = p == null ? "" : "access=" + p;
                        String response;
                        q = encodeUrl(q);
                        p = encodeUrl(p);
                        response =
                                getHtml("AttributeValue.html", new String[][] {{"q", q}, {"p", p}});
                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = this.getHttpMessage(test);
        config.setUrl(msg.getRequestHeader().getURI().toString());
        config.setDoUrlGuess(true);
        config.setUrlGetRequest(true);
        given(scan.getConfig()).willReturn(config);
        urlGuesser = new UrlGuesser(0, scan, httpSender, executor);

        // When
        urlGuesser.run();

        // Then
        ArgumentCaptor<ParamGuessResult> result = ArgumentCaptor.forClass(ParamGuessResult.class);
        verify(scan, times(2)).addParamGuessResult(result.capture());
        assertThat(result.getAllValues(), hasSize(2));
        assertThat(result.getAllValues().get(0).getParamName(), equalTo("q"));
        assertThat(result.getAllValues().get(0).getReasons(), hasSize(5));
        assertThat(result.getAllValues().get(1).getReasons(), hasSize(2));
        assertThat(result.getAllValues().get(1).getParamName(), equalTo("access"));
        assertThat(
                result.getAllValues().get(0).getReasons().get(4),
                equalTo(Reason.PARAM_VALUE_REFLECTION));
        assertThat(
                result.getAllValues().get(0).getReasons().get(1),
                equalTo(Reason.BODY_HEURISTIC_MISMATCH));
    }

    @Test
    void shouldGuessParamsForGivenJsonIncludeString() throws Exception {
        String path = "/json";
        this.nano.addHandler(
                new NanoServerHandler(path) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String parameters = getBody(session);
                        parameters = parameters == null ? " " : parameters;
                        String response;
                        if (parameters.contains("q")) {
                            response = "{\"q\": \"found\", \"z\": \"123\"}";
                        } else if (parameters.contains("access")) {
                            response = "{\"access\": \"111118\", \"z\": \"4321\"}";
                        } else if (parameters.contains("q") && parameters.contains("access")) {
                            response =
                                    "{\"q\": \"111113\", \"access\": \"111118\", \"z\": \"1234321\" }";
                        } else {
                            response = "";
                        }
                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = getHttpMessage(path);
        config.setUrl(msg.getRequestHeader().getURI().toString());
        config.setDoUrlGuess(true);
        config.setUrlJsonRequest(true);
        String jsonIncludeString = "{\"z\":true, $ZAP$}";
        config.setUrlJsonIncludeString(jsonIncludeString);
        given(scan.getConfig()).willReturn(config);
        urlGuesser = new UrlGuesser(0, scan, httpSender, executor);

        // When
        urlGuesser.run();

        // Then
        ArgumentCaptor<ParamGuessResult> result = ArgumentCaptor.forClass(ParamGuessResult.class);
        verify(scan, times(2)).addParamGuessResult(result.capture());
        assertThat(result.getAllValues().get(0).getParamName(), equalTo("q"));
        assertThat(result.getAllValues().get(0).getReasons(), hasSize(3));
        assertThat(result.getAllValues().get(0).getReasons().get(2), equalTo(Reason.TEXT));

        assertThat(result.getAllValues().get(1).getParamName(), equalTo("access"));
        assertThat(result.getAllValues().get(1).getReasons(), hasSize(4));
        assertThat(result.getAllValues().get(1).getReasons().get(2), equalTo(Reason.TEXT));
        assertThat(
                result.getAllValues().get(1).getReasons().get(3),
                equalTo(Reason.PARAM_VALUE_REFLECTION));
    }

    @Test
    void shouldNotGuessParamsIfNoSubstantialChangesAreFound() throws Exception {
        String path = "/test";
        this.nano.addHandler(
                new NanoServerHandler(path) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String response;
                        response =
                                getHtml(
                                        "AttributeValue.html",
                                        new String[][] {{"q", "q=123"}, {"p", "p=4321"}});
                        return newFixedLengthResponse(response);
                    }
                });
        HttpMessage msg = this.getHttpMessage(path);
        config.setUrl(msg.getRequestHeader().getURI().toString());
        config.setDoUrlGuess(true);
        config.setUrlGetRequest(true);
        given(scan.getConfig()).willReturn(config);
        urlGuesser = new UrlGuesser(0, scan, httpSender, executor);

        // When
        urlGuesser.run();

        // Then
        verify(this.scan, times(0)).addParamGuessResult(any());
    }
}
