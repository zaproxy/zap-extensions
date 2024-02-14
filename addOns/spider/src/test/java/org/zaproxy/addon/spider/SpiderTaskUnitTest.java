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
package org.zaproxy.addon.spider;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.sameInstance;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.withSettings;

import java.util.Collections;
import java.util.List;
import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.db.RecordHistory;
import org.parosproxy.paros.db.TableAlert;
import org.parosproxy.paros.db.TableHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.spider.parser.ParseContext;
import org.zaproxy.addon.spider.parser.SpiderParser;
import org.zaproxy.addon.spider.parser.SpiderResourceFound;
import org.zaproxy.zap.model.ValueGenerator;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit test for {@link SpiderTask}. */
class SpiderTaskUnitTest extends TestUtils {

    private TableHistory tableHistory;
    private long sessionId;
    private Session session;

    private SpiderParam options;
    private SpiderController controller;
    private ExtensionSpider2 extensionSpider;
    private ValueGenerator valueGenerator;
    private Spider parent;
    private HttpMessage msg;

    @BeforeEach
    void setUp() throws Exception {
        tableHistory = mock(TableHistory.class, withSettings().strictness(Strictness.LENIENT));
        given(tableHistory.write(anyLong(), anyInt(), any())).willReturn(mock(RecordHistory.class));
        HistoryReference.setTableHistory(tableHistory);
        HistoryReference.setTableAlert(mock(TableAlert.class));

        parent = mock(Spider.class, withSettings().strictness(Strictness.LENIENT));

        options = mock(SpiderParam.class);
        given(parent.getSpiderParam()).willReturn(options);

        Model model = mock(Model.class, withSettings().strictness(Strictness.LENIENT));
        given(parent.getModel()).willReturn(model);

        session = mock(Session.class, withSettings().strictness(Strictness.LENIENT));
        given(model.getSession()).willReturn(session);
        sessionId = 1234;
        given(session.getSessionId()).willReturn(sessionId);

        controller = mock(SpiderController.class);
        given(parent.getController()).willReturn(controller);

        extensionSpider =
                mock(ExtensionSpider2.class, withSettings().strictness(Strictness.LENIENT));
        given(parent.getExtensionSpider()).willReturn(extensionSpider);
        valueGenerator = mock(ValueGenerator.class);
        given(extensionSpider.getValueGenerator()).willReturn(valueGenerator);

        msg = new HttpMessage();
        msg.setRequestHeader("GET /path HTTP/1.1\r\nHost: example.com\r\n");
    }

    @AfterEach
    void cleanUp() {
        HistoryReference.setTableHistory(null);
        HistoryReference.setTableAlert(null);
    }

    @Test
    void shouldPassContextToParsers() {
        // Given
        SpiderParser parser = mock(SpiderParser.class);
        given(parser.canParseResource(any(), anyBoolean())).willReturn(true);
        given(controller.getParsers()).willReturn(Collections.singletonList(parser));
        int depth = 123;
        // When
        SpiderTask.processResource(parent, depth, msg);
        // Then
        ArgumentCaptor<ParseContext> captorCtx = ArgumentCaptor.forClass(ParseContext.class);
        verify(parser).canParseResource(captorCtx.capture(), eq(false));
        ParseContext ctxCanParse = captorCtx.getValue();
        verify(parser).parseResource(captorCtx.capture());
        ParseContext ctxParse = captorCtx.getValue();
        assertThat(ctxCanParse, is(sameInstance(ctxParse)));
        assertThat(ctxParse.getSpiderParam(), is(sameInstance(options)));
        assertThat(ctxParse.getValueGenerator(), is(sameInstance(valueGenerator)));
        assertThat(ctxParse.getHttpMessage(), is(sameInstance(msg)));
        assertThat(ctxParse.getPath(), is(equalTo("/path")));
        assertThat(ctxParse.getDepth(), is(equalTo(depth)));
    }

    @Test
    void shouldHandleParsersExceptions() {
        // Given
        SpiderParser parserA = mock(SpiderParser.class);
        given(parserA.canParseResource(any(), anyBoolean())).willReturn(true);
        given(parserA.parseResource(any())).willThrow(NullPointerException.class);
        SpiderParser parserB = mock(SpiderParser.class);
        given(parserB.canParseResource(any(), anyBoolean())).willReturn(true);
        given(controller.getParsers()).willReturn(List.of(parserA, parserB));
        int depth = 123;
        // When
        SpiderTask.processResource(parent, depth, msg);
        // Then
        verify(parserA).canParseResource(any(), eq(false));
        verify(parserA).parseResource(any());
        verify(parserB).canParseResource(any(), eq(false));
        verify(parserB).parseResource(any());
    }

    @Test
    void shouldPassAlreadyConsumedStateToFollowingParsers() {
        // Given
        SpiderParser parserA = mock(SpiderParser.class);
        given(parserA.canParseResource(any(), anyBoolean())).willReturn(true);
        given(parserA.parseResource(any())).willReturn(true);
        SpiderParser parserB = mock(SpiderParser.class);
        given(parserB.canParseResource(any(), anyBoolean())).willReturn(true);
        given(parserB.parseResource(any())).willReturn(false);
        SpiderParser parserC = mock(SpiderParser.class);
        given(controller.getParsers()).willReturn(List.of(parserA, parserB, parserC));
        int depth = 123;
        // When
        SpiderTask.processResource(parent, depth, msg);
        // Then
        verify(parserA).canParseResource(any(), eq(false));
        verify(parserB).canParseResource(any(), eq(true));
        verify(parserC).canParseResource(any(), eq(true));
    }

    @ParameterizedTest
    @ValueSource(strings = {HttpHeader.HTTP10, HttpHeader.HTTP11, "HTTP/2"})
    void shouldUseHttpVersionFromResourceFound(String httpVersion) throws Exception {
        // Given
        URI uri = new URI("http://127.0.0.1", true);
        SpiderResourceFound resourceFound =
                SpiderResourceFound.builder()
                        .setMethod(HttpRequestHeader.GET)
                        .setUri(uri.toString())
                        .setHttpVersion(httpVersion)
                        .build();
        // When
        new SpiderTask(parent, resourceFound, uri);
        // Then
        HttpMessage msg = messageWrittenToSession();
        assertThat(msg.getRequestHeader().getVersion(), is(equalTo(httpVersion)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "foo=bar", "foo=bar&bar=foo"})
    void shouldAlwaysSetContentLengthResourceFound(String body) throws Exception {
        // Given
        URI uri = new URI("http://example.org/foo", true);
        SpiderResourceFound resourceFound =
                SpiderResourceFound.builder()
                        .setMethod(HttpRequestHeader.POST)
                        .setBody(body)
                        .setUri(uri.toString())
                        .build();
        // When
        new SpiderTask(parent, resourceFound, uri);
        // Then
        HttpMessage msg = messageWrittenToSession();
        String cl = msg.getRequestHeader().getHeader(HttpHeader.CONTENT_LENGTH);
        assertNotNull(cl);
        assertThat(cl, is(equalTo(String.valueOf(body.length()))));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                HttpRequestHeader.GET,
                // CONNECT isn't written to session
                HttpRequestHeader.DELETE,
                HttpRequestHeader.HEAD,
                HttpRequestHeader.TRACE
            })
    void shouldNotSetContentLengthForCertainRequestMethods(String method) throws Exception {
        // Given
        URI uri = new URI("http://example.org/ex?foo=bar", true);
        SpiderResourceFound resourceFound =
                SpiderResourceFound.builder().setMethod(method).setUri(uri.toString()).build();
        // When
        new SpiderTask(parent, resourceFound, uri);
        // Then
        HttpMessage msg = messageWrittenToSession();
        assertNull(msg.getRequestHeader().getHeader(HttpHeader.CONTENT_LENGTH));
    }

    private HttpMessage messageWrittenToSession() throws Exception {
        ArgumentCaptor<HttpMessage> argument = ArgumentCaptor.forClass(HttpMessage.class);
        verify(tableHistory)
                .write(eq(sessionId), eq(HistoryReference.TYPE_SPIDER_TASK), argument.capture());
        return argument.getValue();
    }
}
