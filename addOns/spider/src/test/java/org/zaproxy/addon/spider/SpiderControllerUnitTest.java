/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.withSettings;

import java.util.ArrayList;
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
import org.parosproxy.paros.network.HttpHeaderField;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.spider.parser.SpiderResourceFound;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit test for {@link SpiderController}. */
class SpiderControllerUnitTest extends TestUtils {

    private TableHistory tableHistory;
    private long sessionId;
    private Session session;

    private Spider spider;
    private SpiderController spiderController;

    @BeforeEach
    void setUp() throws Exception {
        tableHistory = mock(TableHistory.class, withSettings().strictness(Strictness.LENIENT));
        given(tableHistory.write(anyLong(), anyInt(), any())).willReturn(mock(RecordHistory.class));
        HistoryReference.setTableHistory(tableHistory);
        HistoryReference.setTableAlert(mock(TableAlert.class));

        spider = mock(Spider.class);

        given(spider.getSpiderParam()).willReturn(new SpiderParam());
        Model model = mock(Model.class, withSettings().strictness(Strictness.LENIENT));
        given(spider.getModel()).willReturn(model);

        session = mock(Session.class, withSettings().strictness(Strictness.LENIENT));
        given(model.getSession()).willReturn(session);
        sessionId = 1234;
        given(session.getSessionId()).willReturn(sessionId);

        spiderController = new SpiderController(spider, Collections.emptyList());
    }

    @AfterEach
    void cleanUp() {
        HistoryReference.setTableHistory(null);
        HistoryReference.setTableAlert(null);
    }

    @ParameterizedTest
    @ValueSource(strings = {HttpHeader.HTTP10, HttpHeader.HTTP11, "HTTP/2"})
    void shouldCreateTaskWithHttpVersionFromAddedSeed(String httpVersion) throws Exception {
        // Given
        URI uri = new URI("http://127.0.0.1", true);
        // When
        spiderController.addSeed(uri, HttpRequestHeader.GET, httpVersion);
        // Then
        HttpMessage msg = messageWrittenToSession();
        assertThat(msg.getRequestHeader().getVersion(), is(equalTo(httpVersion)));
    }

    @Test
    void shouldSubmitTasksForDifferentSpiderResources() {
        // Given
        List<HttpHeaderField> requestHeaders = new ArrayList<>();
        requestHeaders.add(new HttpHeaderField("X-Custom-Header-1", "xyz"));
        // When
        spiderController.resourceFound(
                createBasicGetSpiderResourceFound("https://example.com/test.html", 1));
        spiderController.resourceFound(
                createBasicGetSpiderResourceFound("https://example.com/test.html/", 1));
        spiderController.resourceFound(
                createGetSpiderResourceFoundWithHeaders(
                        "https://example.com/test.html", 1, false, requestHeaders));
        spiderController.resourceFound(
                createBasicPostSpiderResourceFound("https://example.com/test.html", "", 1));
        spiderController.resourceFound(
                createBasicPostSpiderResourceFound("https://example.com/test.html", "A=1", 1));
        spiderController.resourceFound(
                createBasicPostSpiderResourceFound("https://example.com/test.html", "A=2", 1));
        spiderController.resourceFound(
                createPostSpiderResourceFoundWithHeaders(
                        "https://example.com/test.html", "A=2", 1, false, requestHeaders));
        // Then
        verify(spider, times(7)).submitTask(any());
    }

    @Test
    void shouldSubmitTasksForDifferentMethods() {
        // Given
        SpiderResourceFound getResource =
                SpiderResourceFound.builder()
                        .setMethod(HttpRequestHeader.GET)
                        .setUri("http://test.com")
                        .build();
        SpiderResourceFound postResource =
                SpiderResourceFound.builder()
                        .setMethod(HttpRequestHeader.POST)
                        .setUri("http://test.com")
                        .build();
        SpiderResourceFound putResource =
                SpiderResourceFound.builder()
                        .setMethod(HttpRequestHeader.PUT)
                        .setUri("http://test.com")
                        .build();
        SpiderResourceFound deleteResource =
                SpiderResourceFound.builder()
                        .setMethod(HttpRequestHeader.DELETE)
                        .setUri("http://test.com")
                        .build();
        SpiderResourceFound headResource =
                SpiderResourceFound.builder()
                        .setMethod(HttpRequestHeader.HEAD)
                        .setUri("http://test.com")
                        .build();
        // When
        spiderController.resourceFound(getResource);
        spiderController.resourceFound(postResource);
        spiderController.resourceFound(putResource);
        spiderController.resourceFound(deleteResource);
        spiderController.resourceFound(headResource);
        // Then
        verify(spider, times(5)).submitTask(any());
    }

    @Test
    void shouldNotSubmitSameGetTaskWithDifferentDepthAndIgnore() {
        // Given
        SpiderResourceFound spiderResourceFoundDepth1 =
                createGetSpiderResourceFoundWithHeaders(
                        "https://example.com/test.html", 1, false, Collections.emptyList());
        SpiderResourceFound spiderResourceFoundDepth2Ignore =
                createGetSpiderResourceFoundWithHeaders(
                        "https://example.com/test.html", 2, true, Collections.emptyList());
        // When
        spiderController.resourceFound(spiderResourceFoundDepth1);
        spiderController.resourceFound(spiderResourceFoundDepth1);
        spiderController.resourceFound(spiderResourceFoundDepth2Ignore);
        // Then
        verify(spider).submitTask(any());
    }

    @Test
    void shouldNotSubmitSamePostTaskWithDifferentDepthAndIgnore() {
        // Given
        SpiderResourceFound spiderResourceFoundDepth1 =
                createPostSpiderResourceFoundWithHeaders(
                        "https://example.com/test.html", "body", 1, false, Collections.emptyList());
        SpiderResourceFound spiderResourceFoundDepth2Ignore =
                createPostSpiderResourceFoundWithHeaders(
                        "https://example.com/test.html", "body", 2, true, Collections.emptyList());
        // When
        spiderController.resourceFound(spiderResourceFoundDepth1);
        spiderController.resourceFound(spiderResourceFoundDepth1);
        spiderController.resourceFound(spiderResourceFoundDepth2Ignore);
        // Then
        verify(spider).submitTask(any());
    }

    @Test
    void shouldNotSubmitSameGetTaskWithDifferentHeaderOrder() {
        // Given
        List<HttpHeaderField> requestHeadersOrder1 = new ArrayList<>();
        requestHeadersOrder1.add(new HttpHeaderField("X-Custom-Header-1", "xyz"));
        requestHeadersOrder1.add(new HttpHeaderField("X-Custom-Header-2", "123"));
        List<HttpHeaderField> requestHeadersOrder2 = new ArrayList<>();
        requestHeadersOrder2.add(new HttpHeaderField("X-Custom-Header-2", "123"));
        requestHeadersOrder2.add(new HttpHeaderField("X-Custom-Header-1", "xyz"));
        SpiderResourceFound spiderResourceFound1 =
                createGetSpiderResourceFoundWithHeaders(
                        "https://example.com/test.html", 2, false, requestHeadersOrder1);
        SpiderResourceFound spiderResourceFound2 =
                createGetSpiderResourceFoundWithHeaders(
                        "https://example.com/test.html", 2, false, requestHeadersOrder2);
        // When
        spiderController.resourceFound(spiderResourceFound1);
        spiderController.resourceFound(spiderResourceFound2);
        // Then
        verify(spider).submitTask(any());
    }

    @Test
    void shouldNotSubmitSameGetTaskWithDifferentHeaderWhitespaces() {
        // Given
        List<HttpHeaderField> requestHeadersWithoutWS = new ArrayList<>();
        requestHeadersWithoutWS.add(new HttpHeaderField("X-Custom-Header-1", "xyz"));
        List<HttpHeaderField> requestHeadersWithWS = new ArrayList<>();
        requestHeadersWithWS.add(new HttpHeaderField("\tX-Custom-Header-1  ", "\nxyz "));
        SpiderResourceFound spiderResourceFound1 =
                createGetSpiderResourceFoundWithHeaders(
                        "https://example.com/test.html", 2, false, requestHeadersWithoutWS);
        SpiderResourceFound spiderResourceFound2 =
                createGetSpiderResourceFoundWithHeaders(
                        "https://example.com/test.html", 2, false, requestHeadersWithWS);
        // When
        spiderController.resourceFound(spiderResourceFound1);
        spiderController.resourceFound(spiderResourceFound2);
        // Then
        verify(spider).submitTask(any());
    }

    @Test
    void shouldNotSubmitSameGetTaskWithDifferentHeaderCases() {
        // Given
        List<HttpHeaderField> requestHeadersUpperCase = new ArrayList<>();
        requestHeadersUpperCase.add(new HttpHeaderField("X-CUSTOM-HEADER-1", "XYZ"));
        List<HttpHeaderField> requestHeadersLowerCase = new ArrayList<>();
        requestHeadersLowerCase.add(new HttpHeaderField("x-custom-header-1", "xyz"));
        SpiderResourceFound spiderResourceFound1 =
                createGetSpiderResourceFoundWithHeaders(
                        "https://example.com/test.html", 2, false, requestHeadersUpperCase);
        SpiderResourceFound spiderResourceFound2 =
                createGetSpiderResourceFoundWithHeaders(
                        "https://example.com/test.html", 2, false, requestHeadersLowerCase);
        // When
        spiderController.resourceFound(spiderResourceFound1);
        spiderController.resourceFound(spiderResourceFound2);
        // Then
        verify(spider).submitTask(any());
    }

    @Test
    void shouldNotSubmitSameGetTaskWithDuplicateHeaders() {
        // Given
        List<HttpHeaderField> requestHeadersWithoutDuplicates = new ArrayList<>();
        requestHeadersWithoutDuplicates.add(new HttpHeaderField("X-Custom-Header-1", "xyz"));
        List<HttpHeaderField> requestHeadersWithDuplicates = new ArrayList<>();
        requestHeadersWithDuplicates.add(new HttpHeaderField("X-Custom-Header-1", "xyz"));
        requestHeadersWithDuplicates.add(new HttpHeaderField("X-Custom-Header-1", "xyz"));
        requestHeadersWithDuplicates.add(new HttpHeaderField("X-Custom-Header-1", "xyz"));
        SpiderResourceFound spiderResourceFound1 =
                createGetSpiderResourceFoundWithHeaders(
                        "https://example.com/test.html", 2, false, requestHeadersWithoutDuplicates);
        SpiderResourceFound spiderResourceFound2 =
                createGetSpiderResourceFoundWithHeaders(
                        "https://example.com/test.html", 2, false, requestHeadersWithDuplicates);
        // When
        spiderController.resourceFound(spiderResourceFound1);
        spiderController.resourceFound(spiderResourceFound2);
        // Then
        verify(spider).submitTask(any());
    }

    private static SpiderResourceFound createBasicGetSpiderResourceFound(String uri, int depth) {
        return SpiderResourceFound.builder().setDepth(depth).setUri(uri).build();
    }

    private static SpiderResourceFound createGetSpiderResourceFoundWithHeaders(
            String uri, int depth, boolean shouldIgnore, List<HttpHeaderField> requestHeaders) {
        return SpiderResourceFound.builder()
                .setDepth(depth)
                .setUri(uri)
                .setShouldIgnore(shouldIgnore)
                .setHeaders(requestHeaders)
                .build();
    }

    private static SpiderResourceFound createBasicPostSpiderResourceFound(
            String uri, String body, int depth) {
        return SpiderResourceFound.builder()
                .setDepth(depth)
                .setUri(uri)
                .setMethod(HttpRequestHeader.POST)
                .setBody(body)
                .build();
    }

    private static SpiderResourceFound createPostSpiderResourceFoundWithHeaders(
            String uri,
            String body,
            int depth,
            boolean shouldIgnore,
            List<HttpHeaderField> requestHeaders) {
        return SpiderResourceFound.builder()
                .setDepth(depth)
                .setUri(uri)
                .setShouldIgnore(shouldIgnore)
                .setMethod(HttpRequestHeader.POST)
                .setBody(body)
                .setHeaders(requestHeaders)
                .build();
    }

    private HttpMessage messageWrittenToSession() throws Exception {
        ArgumentCaptor<HttpMessage> argument = ArgumentCaptor.forClass(HttpMessage.class);
        verify(tableHistory)
                .write(eq(sessionId), eq(HistoryReference.TYPE_SPIDER_TASK), argument.capture());
        return argument.getValue();
    }
}
