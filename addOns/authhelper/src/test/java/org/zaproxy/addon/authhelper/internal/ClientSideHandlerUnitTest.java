/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
package org.zaproxy.addon.authhelper.internal;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.notNullValue;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import java.util.List;
import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.zaproxy.addon.authhelper.AuthUtils;
import org.zaproxy.addon.authhelper.DiagnosticDataLoader;
import org.zaproxy.addon.authhelper.ExtensionAuthhelper;
import org.zaproxy.addon.authhelper.HistoryProvider;
import org.zaproxy.addon.authhelper.SessionManagementRequestDetails;
import org.zaproxy.addon.authhelper.TestHistoryProvider;
import org.zaproxy.addon.authhelper.internal.ClientSideHandler.AuthRequestDetails;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;
import org.zaproxy.zap.authentication.UsernamePasswordAuthenticationCredentials;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.network.HttpRequestBody;
import org.zaproxy.zap.network.HttpResponseBody;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.users.User;
import org.zaproxy.zap.utils.Pair;

@MockitoSettings(strictness = Strictness.LENIENT)
class ClientSideHandlerUnitTest extends TestUtils {

    private static final String TEST_USERNAME = "test@example.org.com";
    private static final String TEST_PASSWORD = "mySuperSecretPassword";

    private User user;
    private Context context;
    private ClientSideHandler csh;
    private HttpMessageHandlerContext ctx;
    private HistoryProvider historyProvider;

    @Mock(strictness = org.mockito.Mock.Strictness.LENIENT)
    Model model;

    @Mock(strictness = org.mockito.Mock.Strictness.LENIENT)
    Session session;

    private static final String SESSION_TOKEN1 = "1234567890123456789012345678901234567890";

    @BeforeEach
    void setUp() {
        mockMessages(new ExtensionAuthhelper());
        given(model.getSession()).willReturn(session);
        context = new Context(session, 0);
        context.addIncludeInContextRegex("https://example0.*");
        user = mock(User.class);
        given(user.getContext()).willReturn(context);
        UsernamePasswordAuthenticationCredentials creds =
                new UsernamePasswordAuthenticationCredentials(TEST_USERNAME, TEST_PASSWORD);
        given(user.getAuthenticationCredentials()).willReturn(creds);

        csh = new ClientSideHandler(user);
        ctx = new TestHttpMessageHandlerContext();
        historyProvider = new TestHistoryProvider();
        csh.setHistoryProvider(historyProvider);
        AuthUtils.setHistoryProvider(historyProvider);
        Control.initSingletonForTesting(model);
    }

    @AfterEach
    void cleanUp() {
        AuthUtils.clean();
    }

    @Test
    void shouldAddMessageToHistory() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage(new URI("https://example0/", true));
        // When
        csh.handleMessage(ctx, msg);
        // Then
        assertThat(historyProvider.getLastHistoryId(), is(equalTo(1)));
    }

    @Test
    void shouldExtractKeyValuePairs() {
        // Given / When
        List<Pair<String, String>> tokens =
                ClientSideHandler.extractKeyValuePairs(
                        "test{%key1:value1%}test{%key2:value2%}test");
        // Then
        assertThat(tokens.size(), is(equalTo(2)));
        assertThat(tokens.get(0).first, is(equalTo("key1")));
        assertThat(tokens.get(0).second, is(equalTo("value1")));
        assertThat(tokens.get(1).first, is(equalTo("key2")));
        assertThat(tokens.get(1).second, is(equalTo("value2")));
    }

    @Test
    void shouldReturnCorrectMessageUrlTokenCount() throws Exception {
        // Given
        HttpMessage msg =
                new HttpMessage(
                        new HttpRequestHeader(
                                "POST https://www.example.com/test?url1=urlval1&url2=urlval2 HTTP/1.1"));
        List<Pair<String, String>> pairs =
                List.of(new Pair<>("url", "url1"), new Pair<>("url", "url3"));

        // When
        int count = ClientSideHandler.messageTokenCount(msg, pairs);

        // Then
        assertThat(count, is(equalTo(1)));
    }

    @Test
    void shouldReturnCorrectMessageHeaderTokenCount() throws Exception {
        // Given
        HttpMessage msg =
                new HttpMessage(
                        new HttpRequestHeader(
                                "GET https://www.example.com/test?url1=urlval1&url2=urlval2 HTTP/1.1"),
                        new HttpRequestBody(),
                        new HttpResponseHeader(
                                """
    					HTTP/1.1 200 OK
    					header1: headerval1
    					header2: headerval2
    					"""),
                        new HttpResponseBody());
        List<Pair<String, String>> pairs =
                List.of(new Pair<>("header", "header1"), new Pair<>("header", "header3"));

        // When
        int count = ClientSideHandler.messageTokenCount(msg, pairs);

        // Then
        assertThat(count, is(equalTo(1)));
    }

    @Test
    void shouldReturnCorrectMessageJsonTokenCount() throws Exception {
        // Given
        HttpMessage msg =
                new HttpMessage(
                        new HttpRequestHeader(
                                "GET https://www.example.com/test?url1=urlval1&url2=urlval2 HTTP/1.1"),
                        new HttpRequestBody(),
                        new HttpResponseHeader(
                                """
    					HTTP/1.1 200 OK
    					Content-Type: application/json
    					"""),
                        new HttpResponseBody(
                                """
    					{"aaa": {"bbb":"ccc", "ddd":"eee"}}
    					"""));
        List<Pair<String, String>> pairs =
                List.of(new Pair<>("json", "aaa.bbb"), new Pair<>("json", "aaa.fff"));

        // When
        int count = ClientSideHandler.messageTokenCount(msg, pairs);

        // Then
        assertThat(count, is(equalTo(1)));
    }

    @Test
    void shouldReturnCorrectMessageTokenCount() throws Exception {
        // Given
        HttpMessage msg =
                new HttpMessage(
                        new HttpRequestHeader(
                                "POST https://www.example.com/test?url1=urlval1&url2=urlval2 HTTP/1.1"),
                        new HttpRequestBody(),
                        new HttpResponseHeader(
                                """
    					HTTP/1.1 200 OK
    					header1: headerval1
    					header2: headerval2
    					Content-Type: application/json
    					"""),
                        new HttpResponseBody(
                                """
    					{"aaa": {"bbb":"ccc", "ddd":"eee"}}
    					"""));
        List<Pair<String, String>> pairs =
                List.of(
                        new Pair<>("url", "url1"),
                        new Pair<>("url", "url3"),
                        new Pair<>("header", "header1"),
                        new Pair<>("header", "header3"),
                        new Pair<>("json", "aaa.bbb"),
                        new Pair<>("json", "aaa.fff"));

        // When
        int count = ClientSideHandler.messageTokenCount(msg, pairs);

        // Then
        assertThat(count, is(equalTo(3)));
    }

    @Test
    void shouldAddDomainIfCredsDetected() throws Exception {
        // Given
        // This is used to indicate the session management is auto-detect
        AuthUtils.setSessionManagementDetailsForContext(
                0, new SessionManagementRequestDetails(null, null, 0));

        HttpMessage postMsg = new HttpMessage(new URI("https://example.com/", true));
        postMsg.getRequestHeader().setMethod(HttpRequestHeader.POST);
        postMsg.getRequestHeader()
                .setHeader(HttpHeader.CONTENT_TYPE, HttpHeader.FORM_URLENCODED_CONTENT_TYPE);
        postMsg.getRequestBody()
                .setBody(
                        "user="
                                + ExtensionAuthhelper.urlEncode(TEST_USERNAME)
                                + "&pass="
                                + ExtensionAuthhelper.urlEncode(TEST_PASSWORD)
                                + "");
        postMsg.getResponseHeader().setHeader(HttpHeader.SET_COOKIE, "session=" + SESSION_TOKEN1);

        // When
        csh.handleMessage(ctx, postMsg);

        // Then
        assertThat(context.getIncludeInContextRegexs().size(), is(equalTo(2)));
        assertThat(context.getIncludeInContextRegexs().get(0), is(equalTo("https://example0.*")));
        assertThat(
                context.getIncludeInContextRegexs().get(1), is(equalTo("https://example.com.*")));
    }

    @Test
    void shouldNotAddDomainIfPasswordNotDetected() throws Exception {
        // Given
        // This is used to indicate the session management is auto-detect
        AuthUtils.setSessionManagementDetailsForContext(
                0, new SessionManagementRequestDetails(null, null, 0));

        HttpMessage postMsg = new HttpMessage(new URI("https://example.com/", true));
        postMsg.getRequestHeader().setMethod(HttpRequestHeader.POST);
        postMsg.getRequestHeader()
                .setHeader(HttpHeader.CONTENT_TYPE, HttpHeader.FORM_URLENCODED_CONTENT_TYPE);
        postMsg.getRequestBody().setBody("user=" + ExtensionAuthhelper.urlEncode(TEST_USERNAME));
        postMsg.getResponseHeader().setHeader(HttpHeader.SET_COOKIE, "session=" + SESSION_TOKEN1);

        // When
        csh.handleMessage(ctx, postMsg);

        // Then
        assertThat(context.getIncludeInContextRegexs().size(), is(equalTo(1)));
        assertThat(context.getIncludeInContextRegexs().get(0), is(equalTo("https://example0.*")));
    }

    @Test
    void shouldInitAuthRequestDetailsWithGet() throws Exception {
        // Given
        HttpMessage msg =
                new HttpMessage(
                        new HttpRequestHeader(
                                "GET https://example0.com/test?url1=urlval1&url2=urlval2 HTTP/1.1"));

        // When
        csh.handleMessage(ctx, msg);
        AuthRequestDetails arb = csh.getAuthReqDetails();

        // Then
        assertThat(arb.isIncUsername(), is(equalTo(false)));
        assertThat(arb.isIncPassword(), is(equalTo(false)));
    }

    @Test
    void shouldInitAuthRequestDetailsWithPostEncodedData() throws Exception {
        // Given
        HttpMessage postMsg = new HttpMessage(new URI("https://example0/", true));
        postMsg.getRequestHeader().setMethod(HttpRequestHeader.POST);
        postMsg.getRequestHeader()
                .setHeader(HttpHeader.CONTENT_TYPE, HttpHeader.FORM_URLENCODED_CONTENT_TYPE);
        postMsg.getRequestBody()
                .setBody(
                        "user="
                                + ExtensionAuthhelper.urlEncode(TEST_USERNAME)
                                + "&pass="
                                + TEST_PASSWORD
                                + "");

        // When
        csh.handleMessage(ctx, postMsg);
        AuthRequestDetails arb = csh.getAuthReqDetails();

        // Then
        assertThat(arb.isIncUsername(), is(equalTo(true)));
        assertThat(arb.isIncPassword(), is(equalTo(true)));
    }

    @Test
    void shouldInitAuthRequestDetailsWithPostUnencodedData() throws Exception {
        // Given
        HttpMessage postMsg = new HttpMessage(new URI("https://example0/", true));
        postMsg.getRequestHeader().setMethod(HttpRequestHeader.POST);
        postMsg.getRequestHeader().setHeader(HttpHeader.CONTENT_TYPE, HttpHeader.JSON_CONTENT_TYPE);
        postMsg.getRequestBody()
                .setBody("{'user':'" + TEST_USERNAME + "', 'pass':'" + TEST_PASSWORD + "'}");

        // When
        csh.handleMessage(ctx, postMsg);
        AuthRequestDetails arb = csh.getAuthReqDetails();

        // Then
        assertThat(arb.isIncUsername(), is(equalTo(true)));
        assertThat(arb.isIncPassword(), is(equalTo(true)));
    }

    @Test
    void shouldDetectSimpleLogin() throws Exception {
        // Given
        HttpMessage postMsg = new HttpMessage(new URI("https://example0/", true));
        postMsg.getRequestHeader().setMethod(HttpRequestHeader.POST);
        postMsg.getRequestHeader()
                .setHeader(HttpHeader.CONTENT_TYPE, HttpHeader.FORM_URLENCODED_CONTENT_TYPE);
        postMsg.getRequestBody().setBody("user=" + TEST_USERNAME + "&pass=" + TEST_PASSWORD + "");
        postMsg.getResponseHeader().setHeader(HttpHeader.SET_COOKIE, "session=" + SESSION_TOKEN1);

        HttpMessage getMsg = new HttpMessage(new URI("https://www.example.com/", true));
        postMsg.getRequestHeader().setHeader(HttpHeader.COOKIE, "session=" + SESSION_TOKEN1);
        getMsg.getResponseHeader().setHeader(HttpHeader.CONTENT_TYPE, "text/html;charset=UTF-8");
        getMsg.getResponseBody().setBody("Hi test@example.org how are you today?");

        // When
        csh.handleMessage(ctx, postMsg);
        csh.handleMessage(ctx, getMsg);

        // Then
        assertThat(historyProvider.getLastHistoryId(), is(equalTo(2)));
        assertThat(csh.getAuthMsg().getHistoryRef().getHistoryId(), is(equalTo(1)));
    }

    @Test
    void shouldDetectBodgeitLogin() throws Exception {
        // Given
        List<HttpMessage> msgs =
                DiagnosticDataLoader.loadTestData(this.getResourcePath("bodgeit.diags").toFile());

        // When
        msgs.forEach(msg -> csh.handleMessage(ctx, msg));

        // Then
        assertThat(historyProvider.getLastHistoryId(), is(equalTo(3)));
        assertThat(csh.getAuthMsg(), is(notNullValue()));
        assertThat(csh.getAuthMsg().getHistoryRef().getHistoryId(), is(equalTo(2)));
        assertThat(
                csh.getAuthMsg().getRequestHeader().getURI().toString(),
                is(equalTo("https://example0/login.jsp")));
        assertThat(csh.getAuthMsg().getRequestHeader().getMethod(), is(equalTo("POST")));
        assertThat(
                csh.getAuthMsg().getRequestBody().toString(),
                is(equalTo("password=F4keP4ssw0rd&username=FakeUserName@example.com&\n")));
    }

    @Test
    void shouldDetectCtflearnLogin() throws Exception {
        // Given
        List<HttpMessage> msgs =
                DiagnosticDataLoader.loadTestData(this.getResourcePath("ctflearn.diags").toFile());

        // When
        msgs.forEach(msg -> csh.handleMessage(ctx, msg));

        // Then
        assertThat(historyProvider.getLastHistoryId(), is(equalTo(21)));
        assertThat(csh.getAuthMsg(), is(notNullValue()));
        assertThat(csh.getAuthMsg().getHistoryRef().getHistoryId(), is(equalTo(10)));
        assertThat(
                csh.getAuthMsg().getRequestHeader().getURI().toString(),
                is(equalTo("https://example0/login")));
        assertThat(csh.getAuthMsg().getRequestHeader().getMethod(), is(equalTo("POST")));
        assertThat(
                csh.getAuthMsg().getRequestBody().toString(),
                is(
                        equalTo(
                                "csrf_token=sanitizedtoken23&identifier=FakeUserName@example.com&password=F4keP4ssw0rd&\n")));
    }

    @Test
    void shouldDetectDefthewebLogin() throws Exception {
        // Given
        List<HttpMessage> msgs =
                DiagnosticDataLoader.loadTestData(this.getResourcePath("deftheweb.diags").toFile());

        // When
        msgs.forEach(msg -> csh.handleMessage(ctx, msg));

        // Then
        assertThat(historyProvider.getLastHistoryId(), is(equalTo(20)));
        assertThat(csh.getAuthMsg(), is(notNullValue()));
        assertThat(csh.getAuthMsg().getHistoryRef().getHistoryId(), is(equalTo(7)));
        assertThat(
                csh.getAuthMsg().getRequestHeader().getURI().toString(),
                is(equalTo("https://example0/auth")));
        assertThat(csh.getAuthMsg().getRequestHeader().getMethod(), is(equalTo("POST")));
        assertThat(
                csh.getAuthMsg().getRequestBody().toString(),
                is(
                        equalTo(
                                "password=F4keP4ssw0rd&token=sanitizedtoken12&username=FakeUserName@example.com&\n")));
    }

    @Test
    void shouldDetectGinnjuiceLogin() throws Exception {
        // Given
        List<HttpMessage> msgs =
                DiagnosticDataLoader.loadTestData(this.getResourcePath("ginnjuice.diags").toFile());

        // When
        msgs.forEach(msg -> csh.handleMessage(ctx, msg));

        // Then
        assertThat(historyProvider.getLastHistoryId(), is(equalTo(3)));
        assertThat(csh.getAuthMsg(), is(notNullValue()));
        assertThat(csh.getAuthMsg().getHistoryRef().getHistoryId(), is(equalTo(2)));
        assertThat(
                csh.getAuthMsg().getRequestHeader().getURI().toString(),
                is(equalTo("https://example0/login")));
        assertThat(csh.getAuthMsg().getRequestHeader().getMethod(), is(equalTo("POST")));
        assertThat(
                csh.getAuthMsg().getRequestBody().toString(),
                is(equalTo("csrf=sanitizedtoken3&username=FakeUserName@example.com&\n")));
    }

    @Test
    void shouldDetectInfosecexLogin() throws Exception {
        // Given
        List<HttpMessage> msgs =
                DiagnosticDataLoader.loadTestData(this.getResourcePath("infosecex.diags").toFile());

        // When
        msgs.forEach(msg -> csh.handleMessage(ctx, msg));

        // Then
        assertThat(historyProvider.getLastHistoryId(), is(equalTo(16)));
        assertThat(csh.getAuthMsg(), is(notNullValue()));
        assertThat(csh.getAuthMsg().getHistoryRef().getHistoryId(), is(equalTo(2)));
        assertThat(
                csh.getAuthMsg().getRequestHeader().getURI().toString(),
                is(equalTo("https://example0/sign_in")));
        assertThat(csh.getAuthMsg().getRequestHeader().getMethod(), is(equalTo("POST")));
        assertThat(
                csh.getAuthMsg().getRequestBody().toString(),
                is(
                        equalTo(
                                "authenticity_token=sanitizedtoken1&button=sanitizedtoken2&user[email]=FakeUserName@example.com&user[password]=F4keP4ssw0rd&\n")));
    }

    class TestHttpMessageHandlerContext implements HttpMessageHandlerContext {

        @Override
        public boolean isRecursive() {
            return false;
        }

        @Override
        public boolean isExcluded() {
            return false;
        }

        @Override
        public boolean isFromClient() {
            return false;
        }

        @Override
        public void overridden() {}

        @Override
        public void close() {}
    }
}
