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
package org.zaproxy.addon.exim.sites;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.StringWriter;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.VariantMultipartFormParameters;
import org.parosproxy.paros.db.RecordHistory;
import org.parosproxy.paros.db.TableAlert;
import org.parosproxy.paros.db.TableHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.model.SiteMap;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.exim.ExporterResult;
import org.zaproxy.zap.extension.ascan.VariantFactory;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.model.StandardParameterParser;
import org.zaproxy.zap.model.StructuralNodeModifier;
import org.zaproxy.zap.model.StructuralNodeModifier.Type;
import org.zaproxy.zap.utils.I18N;

/** Unit test for {@link SitesTreeHandler}. */
class SiteTreeHandlerUnitTest {

    private static final byte[] MULTIPART_BODY_BYTES =
            """
            -----------12345\r
            Content-Disposition: form-data; name="x"\r\n\r
            Data
            -----------12345--\r
            """
                    .getBytes();
    private SiteMap siteMap;
    private Session session;
    private StandardParameterParser spp;

    @BeforeEach
    void setup() throws Exception {
        Constant.messages = new I18N(Locale.ENGLISH);

        TableHistory tableHistory = mock(TableHistory.class);
        session = mock(Session.class);
        spp = new StandardParameterParser();
        given(session.getUrlParamParser(any(String.class))).willReturn(spp);
        given(session.getFormParamParser(any(String.class))).willReturn(spp);
        given(session.getParameters(any(HttpMessage.class), any(HtmlParameter.Type.class)))
                .willCallRealMethod();
        Long sessionId = 1234L;

        given(session.getSessionId()).willReturn(sessionId);
        given(
                        tableHistory.write(
                                any(Long.class),
                                eq(HistoryReference.TYPE_TEMPORARY),
                                any(HttpMessage.class)))
                .willReturn(mock(RecordHistory.class));
        HistoryReference.setTableHistory(tableHistory);

        TableAlert tableAlert = mock(TableAlert.class);
        given(tableAlert.getAlertsBySourceHistoryId(anyInt())).willReturn(Collections.emptyList());
        HistoryReference.setTableAlert(tableAlert);

        Model model = mock(Model.class);
        Model.setSingletonForTesting(model);
        Control.initSingletonForTesting(model);
        given(model.getSession()).willReturn(session);

        VariantFactory factory = new VariantFactory();
        factory.addVariant(VariantMultipartFormParameters.class);
        given(model.getVariantFactory()).willReturn(factory);

        SiteNode rootNode = new SiteNode(null, -1, "Root Node");
        siteMap = new SiteMap(rootNode, model);
    }

    @Test
    void shouldReportErrorIfNoFile() {
        // Given
        File f = new File("should-not-exist");

        // When
        PruneSiteResult result = SitesTreeHandler.pruneSiteNodes(f);

        // Then
        assertThat(result.getError(), is(equalTo("!exim.sites.error.prune.exception!")));
    }

    private HistoryReference getHref(String url, String method) throws Exception {
        HttpMessage msg = new HttpMessage(new URI(url, true));
        msg.getRequestHeader().setMethod(method);
        return getHref(msg);
    }

    private HistoryReference getHref(HttpMessage msg) throws Exception {
        HistoryReference href = mock(HistoryReference.class);
        given(href.getURI()).willReturn(msg.getRequestHeader().getURI());
        given(href.getMethod()).willReturn(msg.getRequestHeader().getMethod());
        given(href.getStatusCode()).willReturn(msg.getResponseHeader().getStatusCode());
        given(href.getResponseHeaderLength())
                .willReturn(msg.getResponseHeader().toString().length());
        given(href.getResponseBodyLength()).willReturn(msg.getResponseBody().length());

        msg.setHistoryRef(href);
        given(href.getHttpMessage()).willReturn(msg);
        return href;
    }

    @Test
    void shouldOutputNodeWithData() throws Exception {
        // Given
        String expectedYaml =
                "- node: Sites\n"
                        + "  children:\n"
                        + "  - node: https://www.example.com\n"
                        + "    url: https://www.example.com?aa=bb&cc=dd\n"
                        + "    method: POST\n"
                        + "    responseLength: 61\n"
                        + "    statusCode: 200\n"
                        + "    data: eee=&ggg=\n";
        HttpMessage msg =
                new HttpMessage(
                        "POST https://www.example.com?aa=bb&cc=dd HTTP/1.1\r\n"
                                + "Content-Type: text/html; charset=UTF-8\r\n",
                        "eee=fff&ggg=hhh".getBytes(),
                        "HTTP/1.1 200 OK\r\n" + "content-length: 20",
                        "12345678901234567890".getBytes());
        siteMap.addPath(getHref(msg));
        StringWriter sw = new StringWriter();
        ExporterResult result = new ExporterResult();

        // When
        SitesTreeHandler.exportSitesTree(sw, siteMap, result);

        // Then
        assertThat(sw.toString(), is(expectedYaml));
        assertThat(result.getCount(), is(2));
    }

    @Test
    void shouldOutputNodeWithDataButNoContentType() throws Exception {
        // Given
        String expectedYaml =
                "- node: Sites\n"
                        + "  children:\n"
                        + "  - node: https://www.example.com\n"
                        + "    url: https://www.example.com?aa=bb&cc=dd\n"
                        + "    method: POST\n"
                        + "    responseLength: 61\n"
                        + "    statusCode: 200\n"
                        + "    data: eee=&ggg=\n";
        HttpMessage msg =
                new HttpMessage(
                        "POST https://www.example.com?aa=bb&cc=dd HTTP/1.1\r\n",
                        "eee=fff&ggg=hhh".getBytes(),
                        "HTTP/1.1 200 OK\r\n" + "content-length: 20",
                        "12345678901234567890".getBytes());
        siteMap.addPath(getHref(msg));
        StringWriter sw = new StringWriter();
        ExporterResult result = new ExporterResult();

        // When
        SitesTreeHandler.exportSitesTree(sw, siteMap, result);

        // Then
        assertThat(sw.toString(), is(expectedYaml));
        assertThat(result.getCount(), is(2));
    }

    @Test
    void shouldOutputNodes() throws Exception {
        // Given
        String expectedYaml =
                "- node: Sites\n"
                        + "  children:\n"
                        + "  - node: https://www.example.com\n"
                        + "    url: https://www.example.com\n"
                        + "    method: GET\n"
                        + "    children:\n"
                        + "    - node: POST:/()(aaa)\n"
                        + "      url: https://www.example.com/\n"
                        + "      method: POST\n"
                        + "      responseLength: 61\n"
                        + "      statusCode: 200\n"
                        + "      data: aaa=\n"
                        + "    - node: PUT:aaa\n"
                        + "      url: https://www.example.com/aaa\n"
                        + "      method: PUT\n";
        HttpMessage msg =
                new HttpMessage(
                        "POST https://www.example.com/ HTTP/1.1\r\n",
                        "aaa=bbb".getBytes(),
                        "HTTP/1.1 200 OK\r\n" + "content-length: 20",
                        "12345678901234567890".getBytes());
        siteMap.addPath(getHref(msg));
        siteMap.addPath(getHref("https://www.example.com/aaa", "PUT"));

        StringWriter sw = new StringWriter();
        ExporterResult result = new ExporterResult();

        // When
        SitesTreeHandler.exportSitesTree(sw, siteMap, result);

        // Then
        assertThat(sw.toString(), is(expectedYaml));
        assertThat(result.getCount(), is(4));
    }

    @Test
    void shouldOutputNodeWithMultipartFormData() throws Exception {
        // Given
        String expectedYaml =
                "- node: Sites\n"
                        + "  children:\n"
                        + "  - node: https://www.example.com\n"
                        + "    url: https://www.example.com\n"
                        + "    method: GET\n"
                        + "    children:\n"
                        + "    - node: \"POST:/(bb,dd)(multipart:x)\"\n"
                        + "      url: https://www.example.com/?bb=bcc&dd=ee\n"
                        + "      method: POST\n"
                        + "      responseLength: 61\n"
                        + "      statusCode: 200\n"
                        + "      data: x\n";
        HttpMessage msg =
                new HttpMessage(
                        """
                        POST https://www.example.com/?bb=bcc&dd=ee HTTP/1.1
                        Content-Type: multipart/form-data; boundary=-----------12345
                        """,
                        MULTIPART_BODY_BYTES,
                        "HTTP/1.1 200 OK\r\n" + "content-length: 20",
                        "12345678901234567890".getBytes());
        siteMap.addPath(getHref(msg));
        StringWriter sw = new StringWriter();
        ExporterResult result = new ExporterResult();

        // When
        SitesTreeHandler.exportSitesTree(sw, siteMap, result);

        // Then
        assertThat(sw.toString(), is(expectedYaml));
        assertThat(result.getCount(), is(3));
    }

    @Test
    void shouldOutputDdnNode() throws Exception {
        // Given
        Context context = new Context(session, 1);
        context.addIncludeInContextRegex("https://www.example.com.*");
        Pattern p = Pattern.compile("https://www.example.com/(app/)(.+?)(/.*)");
        StructuralNodeModifier ddn = new StructuralNodeModifier(Type.DataDrivenNode, p, "DDN1");
        context.addDataDrivenNodes(ddn);
        spp.setContext(context);
        String expectedYaml =
                "- node: Sites\n"
                        + "  children:\n"
                        + "  - node: https://www.example.com\n"
                        + "    url: https://www.example.com\n"
                        + "    method: GET\n"
                        + "    children:\n"
                        + "    - node: app\n"
                        + "      url: https://www.example.com/app\n"
                        + "      method: GET\n"
                        + "      children:\n"
                        + "      - node: «DDN1»\n"
                        + "        url: https://www.example.com/app/company1\n"
                        + "        method: GET\n"
                        + "        children:\n"
                        + "        - node: GET:aaa?ddd=eee(ddd)\n"
                        + "          url: https://www.example.com/app/company1/aaa?ddd=eee\n"
                        + "          method: GET\n";
        siteMap.addPath(getHref("https://www.example.com/app/company1/aaa?ddd=eee", "GET"));
        siteMap.addPath(getHref("https://www.example.com/app/company2/aaa?ddd=eee", "GET"));
        siteMap.addPath(getHref("https://www.example.com/app/company3/aaa?ddd=eee", "GET"));

        StringWriter sw = new StringWriter();
        ExporterResult result = new ExporterResult();

        // When
        SitesTreeHandler.exportSitesTree(sw, siteMap, result);

        // Then
        assertThat(sw.toString(), is(expectedYaml));
        assertThat(result.getCount(), is(5));
    }

    @Test
    void shoulErrorIfBadYaml() throws Exception {
        // Given / When
        PruneSiteResult res =
                SitesTreeHandler.pruneSiteNodes(
                        new ByteArrayInputStream(
                                "This is not yaml".getBytes(StandardCharsets.UTF_8)),
                        siteMap);

        // Check the results
        assertThat(res.getReadNodes(), is(0));
        assertThat(res.getDeletedNodes(), is(0));
        assertThat(res.getError(), is("!exim.sites.error.prune.badformat!"));
    }

    @Test
    void shouldPruneOneNode() throws Exception {
        // Given
        SiteNode exNode = siteMap.addPath(getHref("https://www.example.com/", "GET"));

        int rootCount = 0;
        int exCount = 0;
        if (exNode != null) {
            rootCount = siteMap.getRoot().getChildCount();
            exCount = siteMap.getRoot().getChildAt(0).getChildCount();
        }
        PruneSiteResult res = new PruneSiteResult();

        // When
        SitesTreeHandler.pruneSiteNodes(
                getExImSiteNode("https://www.example.com/", "GET"), res, siteMap);

        // Check it did get setup correctly
        assertThat(exNode, is(notNullValue()));
        assertThat(rootCount, is(1));
        assertThat(exCount, is(1));

        // Check the results
        assertThat(res.getReadNodes(), is(1));
        assertThat(res.getDeletedNodes(), is(1));
        assertThat(res.getError(), is(nullValue()));

        // And that the node really was deleted
        assertThat(siteMap.getRoot().getChildCount(), is(1));
        assertThat(siteMap.getRoot().getChildAt(0).getChildCount(), is(0));
    }

    private static EximSiteNode getExImSiteNode(String url, String method) {
        return getExImSiteNode(url, method, method + ":" + url);
    }

    private static EximSiteNode getExImSiteNode(String url, String method, String name) {
        EximSiteNode node = new EximSiteNode();
        node.setNode(name);
        node.setMethod(method);
        node.setUrl(url);
        return node;
    }

    @Test
    void shouldPruneAllNodes() throws Exception {
        // Given
        siteMap.addPath(getHref("https://www.example.com/", "GET"));
        siteMap.addPath(getHref("https://www.example.com/aaa", "GET"));
        siteMap.addPath(getHref("https://www.example.com/bbb", "GET"));
        siteMap.addPath(getHref("https://www.example.com/ccc", "GET"));

        PruneSiteResult res = new PruneSiteResult();

        EximSiteNode exNode = getExImSiteNode("https://www.example.com", "GET");
        EximSiteNode slNode = getExImSiteNode("https://www.example.com/", "GET");
        EximSiteNode aaaNode = getExImSiteNode("https://www.example.com/aaa", "GET");
        EximSiteNode bbbNode = getExImSiteNode("https://www.example.com/bbb", "GET");
        EximSiteNode cccNode = getExImSiteNode("https://www.example.com/ccc", "GET");
        exNode.setChildren(List.of(slNode, aaaNode, bbbNode, cccNode));

        // When
        SitesTreeHandler.pruneSiteNodes(exNode, res, siteMap);

        // Check the results
        assertThat(res.getReadNodes(), is(5));
        assertThat(res.getDeletedNodes(), is(5));
        assertThat(res.getError(), is(nullValue()));

        // And that the node really was deleted
        assertThat(siteMap.getRoot().getChildCount(), is(0));
    }

    @Test
    void shouldLeaveNodes() throws Exception {
        // Given
        siteMap.addPath(getHref("https://www.example.com/", "GET"));
        siteMap.addPath(getHref("https://www.example.com/aaa", "GET"));
        siteMap.addPath(getHref("https://www.example.com/bbb", "GET"));
        siteMap.addPath(getHref("https://www.example.com/ccc", "GET"));

        PruneSiteResult res = new PruneSiteResult();

        EximSiteNode exNode = getExImSiteNode("https://www.example.com", "GET");
        EximSiteNode slNode = getExImSiteNode("https://www.example.com/", "GET");
        EximSiteNode aaaNode = getExImSiteNode("https://www.example.com/aaa", "GET");
        EximSiteNode bbbNode = getExImSiteNode("https://www.example.com/bbb", "GET");
        exNode.setChildren(List.of(slNode, aaaNode, bbbNode));

        // When
        SitesTreeHandler.pruneSiteNodes(exNode, res, siteMap);

        // Check the results
        assertThat(res.getReadNodes(), is(4));
        assertThat(res.getDeletedNodes(), is(3));
        assertThat(res.getError(), is(nullValue()));

        // And that the node really was deleted
        assertThat(siteMap.getRoot().getChildCount(), is(1));
        assertThat(siteMap.getRoot().getChildAt(0).toString(), is("https://www.example.com"));
        assertThat(siteMap.getRoot().getChildAt(0).getChildCount(), is(1));
        assertThat(siteMap.getRoot().getChildAt(0).getChildAt(0).toString(), is("GET:ccc"));
        assertThat(siteMap.getRoot().getChildAt(0).getChildAt(0).getChildCount(), is(0));
    }

    @Test
    void shouldPruneNodeWithMultipartFormData() throws Exception {
        // Given
        HttpMessage msg =
                new HttpMessage(
                        "POST https://www.example.com/?bb=bcc&dd=ee HTTP/1.1\r\n"
                                + "Content-Type: multipart/form-data; boundary=-----------12345\r\n",
                        MULTIPART_BODY_BYTES,
                        "HTTP/1.1 200 OK\r\n" + "content-length: 20",
                        "12345678901234567890".getBytes());
        siteMap.addPath(getHref(msg));
        EximSiteNode node =
                getExImSiteNode(
                        "https://www.example.com/?bb=bcc&dd=ee",
                        "POST",
                        "POST:/(bb,dd)(multipart:x)");
        node.setData("x");

        PruneSiteResult res = new PruneSiteResult();

        // When
        SitesTreeHandler.pruneSiteNodes(node, res, siteMap);

        // Then
        assertThat(res.getReadNodes(), is(1));
        assertThat(res.getDeletedNodes(), is(1));
        assertThat(res.getError(), is(nullValue()));
    }

    @Test
    void shoulPruneDdnNode() throws Exception {
        // Given
        Context context = new Context(session, 1);
        context.addIncludeInContextRegex("https://www.example.com.*");
        Pattern p = Pattern.compile("https://www.example.com/(app/)(.+?)(/.*)");
        StructuralNodeModifier ddn = new StructuralNodeModifier(Type.DataDrivenNode, p, "DDN1");
        context.addDataDrivenNodes(ddn);
        spp.setContext(context);
        String yaml =
                "- node: Sites\n"
                        + "  children:\n"
                        + "  - node: https://www.example.com\n"
                        + "    url: https://www.example.com\n"
                        + "    method: GET\n"
                        + "    children:\n"
                        + "    - node: app\n"
                        + "      url: https://www.example.com/app\n"
                        + "      method: GET\n"
                        + "      children:\n"
                        + "      - node: «DDN1»\n"
                        + "        url: https://www.example.com/app/company1\n"
                        + "        method: GET\n"
                        + "        children:\n"
                        + "        - node: GET:aaa?ddd=eee(ddd)\n"
                        + "          url: https://www.example.com/app/company1/aaa?ddd=eee\n"
                        + "          method: GET\n";
        siteMap.addPath(getHref("https://www.example.com/app/company1/aaa?ddd=eee", "GET"));
        siteMap.addPath(getHref("https://www.example.com/app/company2/aaa?ddd=eee", "GET"));
        siteMap.addPath(getHref("https://www.example.com/app/company3/aaa?ddd=eee", "GET"));

        // When
        PruneSiteResult res =
                SitesTreeHandler.pruneSiteNodes(
                        new ByteArrayInputStream(yaml.getBytes(StandardCharsets.UTF_8)), siteMap);

        // Check the results
        assertThat(res.getReadNodes(), is(4));
        assertThat(res.getDeletedNodes(), is(4));
        assertThat(res.getError(), is(nullValue()));

        // And that the node hierarchy really was deleted
        assertThat(siteMap.getRoot().getChildCount(), is(0));
    }

    static Stream<Arguments> specialParameterNames() {
        return Stream.of(
                Arguments.of("\"", "%22"),
                Arguments.of("'", "%27"),
                Arguments.of("\\", "%5C"),
                Arguments.of("\n", "%0A"),
                Arguments.of("\r", "%0D"),
                Arguments.of("\u0001", "%01"),
                Arguments.of("\u0002", "%02"),
                Arguments.of("\u0003", "%03"));
    }

    @ParameterizedTest
    @MethodSource("specialParameterNames")
    void shouldHandleSpecialCharactersInParameterNames(
            String parameterName, String persistedParameterName) throws Exception {
        // Given
        HttpMessage msg =
                new HttpMessage(
                        "POST https://www.example.com HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded; charset=UTF-8\r\n",
                        (parameterName + "=fff").getBytes(),
                        "HTTP/1.1 200 OK\r\ncontent-length: 0",
                        "".getBytes());
        siteMap.addPath(getHref(msg));

        StringWriter sw = new StringWriter();
        ExporterResult result = new ExporterResult();

        // When
        SitesTreeHandler.exportSitesTree(sw, siteMap, result);

        // Then
        assertThat(
                sw.toString(),
                containsString(
                        """
                        data: '%s='
                        """
                                .formatted(persistedParameterName)));
    }

    static Stream<Arguments> specialNodeNames() {
        return Stream.of(
                Arguments.of("\"", "POST:\""),
                Arguments.of("'", "POST:'"),
                Arguments.of("\\", "POST:\\"),
                Arguments.of("\n", "|\n        POST:"),
                Arguments.of("\r", "\"POST:\\r\""),
                Arguments.of("\u0001", "\"POST:\\x01\""),
                Arguments.of("\u0002", "\"POST:\\x02\""),
                Arguments.of("\u0003", "\"POST:\\x03\""));
    }

    @ParameterizedTest
    @MethodSource("specialNodeNames")
    void shouldHandleSpecialCharactersInNodeNames(String nodeName, String persistedNodeName)
            throws Exception {
        // Given
        HttpMessage msg =
                new HttpMessage(
                        "POST https://www.example.com/%s HTTP/1.1\r\n"
                                .formatted(URLEncoder.encode(nodeName, StandardCharsets.UTF_8)),
                        "".getBytes(),
                        "HTTP/1.1 200 OK\r\ncontent-length: 0",
                        "".getBytes());
        siteMap.addPath(getHref(msg));

        StringWriter sw = new StringWriter();
        ExporterResult result = new ExporterResult();

        // When
        SitesTreeHandler.exportSitesTree(sw, siteMap, result);

        // Then
        assertThat(
                sw.toString(),
                containsString(
                        """
                        - node: %s
                        """
                                .formatted(persistedNodeName)));
    }
}
