/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.zaproxy.addon.authhelper;

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.notNullValue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.withSettings;

import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.zaproxy.addon.authhelper.HeaderBasedSessionManagementMethodType.HeaderBasedSessionManagementMethod;
import org.zaproxy.zap.authentication.AuthenticationMethod;
import org.zaproxy.zap.authentication.AuthenticationMethod.AuthCheckingStrategy;
import org.zaproxy.zap.extension.pscan.PassiveScanActions;
import org.zaproxy.zap.extension.pscan.PassiveScanData;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.network.HttpRequestBody;
import org.zaproxy.zap.network.HttpResponseBody;
import org.zaproxy.zap.session.SessionManagementMethod;
import org.zaproxy.zap.utils.I18N;

/** Unit test for {@link SessionDetectionScanRule}. */
class SessionDetectionScanRuleUnitTest extends PassiveScannerTest<SessionDetectionScanRule> {

    private HistoryProvider historyProvider;

    @Override
    protected SessionDetectionScanRule createScanner() {
        return new SessionDetectionScanRule();
    }

    private ExtensionLoader extensionLoader;

    private Context context;
    private Model model;

    @AfterEach
    void cleanUp() {
        AuthUtils.clean();
    }

    @Test
    void shouldSetHeaderBasedSessionManagment() throws Exception {
        // Given
        Constant.messages = mock(I18N.class);
        model = mock(Model.class);
        extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        context = mock(Context.class);
        AutoDetectSessionManagementMethodType adsmt = new AutoDetectSessionManagementMethodType();
        AuthenticationMethod authMethod = mock(AuthenticationMethod.class);
        given(context.getSessionManagementMethod())
                .willReturn(adsmt.createSessionManagementMethod(1));
        given(context.getAuthenticationMethod()).willReturn(authMethod);
        given(authMethod.getAuthCheckingStrategy()).willReturn(mock(AuthCheckingStrategy.class));

        Control.initSingletonForTesting(model, extensionLoader);
        Model.setSingletonForTesting(model);

        Session session = mock(Session.class);
        given(session.getContextsForUrl(anyString())).willReturn(Arrays.asList(context));
        given(model.getSession()).willReturn(session);

        historyProvider = new TestHistoryProvider();
        AuthUtils.setHistoryProvider(historyProvider);

        String body = "Response Body";
        String token = "12345678901234567890";
        HttpMessage msg =
                new HttpMessage(
                        new HttpRequestHeader(
                                "GET / HTTP/1.1\r\n"
                                        + "Header1: Value1\r\n"
                                        + "Header2: Value2\r\n"
                                        + "Authorization: "
                                        + token
                                        + "\r\n"
                                        + "Host: example.com\r\n\r\n"),
                        new HttpRequestBody("Request Body"),
                        new HttpResponseHeader("HTTP/1.1 200 OK\r\n"),
                        new HttpResponseBody(body));

        AuthUtils.recordSessionToken(
                new SessionToken(SessionToken.HEADER_SOURCE, "Authorization", token));
        PassiveScanData helper = mock(PassiveScanData.class);
        SessionDetectionScanRule rule = this.createScanner();
        rule.setHelper(helper);
        rule.setPassiveScanActions(mock(PassiveScanActions.class));

        // When
        rule.scanHttpResponseReceive(msg, 1, null);

        // Then
        ArgumentCaptor<SessionManagementMethod> captor =
                ArgumentCaptor.forClass(SessionManagementMethod.class);
        verify(context).setSessionManagementMethod(captor.capture());

        assertThat(captor.getValue(), instanceOf(HeaderBasedSessionManagementMethod.class));
        HeaderBasedSessionManagementMethod hbsmm =
                (HeaderBasedSessionManagementMethod) captor.getValue();
        assertThat(hbsmm.getHeaderConfigs().size(), is(equalTo(1)));
        assertThat(hbsmm.getHeaderConfigs().get(0).first, is(equalTo("Authorization")));
        assertThat(hbsmm.getHeaderConfigs().get(0).second, is(equalTo("{%header:Authorization%}")));
    }

    @Test
    void shouldCacheSessionToken() throws Exception {
        // Given
        Constant.messages = mock(I18N.class);
        model = mock(Model.class);
        extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));

        Control.initSingletonForTesting(model, extensionLoader);
        Model.setSingletonForTesting(model);

        Session session = mock(Session.class);
        given(session.getContextsForUrl(anyString())).willReturn(Arrays.asList());
        given(model.getSession()).willReturn(session);

        String body = "Response Body";
        String token = "67890123456789012345";
        HttpMessage msg =
                new HttpMessage(
                        new HttpRequestHeader(
                                "GET / HTTP/1.1\r\n"
                                        + "Header1: Value1\r\n"
                                        + "Header2: Value2\r\n"
                                        + "Authorization: "
                                        + token
                                        + "\r\n"
                                        + "Host: example.com\r\n\r\n"),
                        new HttpRequestBody("Request Body"),
                        new HttpResponseHeader("HTTP/1.1 200 OK\r\n"),
                        new HttpResponseBody(body));

        AuthUtils.recordSessionToken(
                new SessionToken(SessionToken.HEADER_SOURCE, "Authorization", token));
        PassiveScanData helper = mock(PassiveScanData.class);
        SessionDetectionScanRule rule = this.createScanner();
        rule.setHelper(helper);
        rule.setPassiveScanActions(mock(PassiveScanActions.class));

        // When
        rule.scanHttpResponseReceive(msg, 1, null);

        // Then
        assertThat(AuthUtils.getSessionToken(token), is(notNullValue()));
        assertThat(AuthUtils.getSessionToken(token).getKey(), is("Authorization"));
        assertThat(AuthUtils.getSessionToken(token).getValue(), is(token));
    }

    @Test
    void shouldDetectBodgeitSession() throws Exception {
        // Given
        List<HttpMessage> msgs =
                DiagnosticDataLoader.loadTestData(
                        this.getResourcePath("internal/bodgeit.diags").toFile());

        historyProvider = new TestHistoryProvider();
        AuthUtils.setHistoryProvider(historyProvider);
        // When
        msgs.forEach(
                msg -> {
                    PassiveScanData helper2 = new PassiveScanData(msg);
                    rule.setHelper(helper2);
                    rule.setPassiveScanActions(actions);
                    rule.scanHttpResponseReceive(msg, 1, null);
                });

        // Then
        assertThat(alertsRaised.size(), is(equalTo(1)));
        assertThat(alertsRaised.get(0).getUri(), is(equalTo("https://example0/login.jsp")));
        assertThat(alertsRaised.get(0).getMethod(), is(equalTo("GET")));
        assertThat(alertsRaised.get(0).getEvidence(), is(equalTo("JSESSIONID")));
        assertThat(alertsRaised.get(0).getOtherInfo(), is(equalTo("cookie:JSESSIONID")));
        assertThat(alertsRaised.get(0).getConfidence(), is(equalTo(Alert.CONFIDENCE_MEDIUM)));
    }

    @Test
    void shouldDetectCtflearnSession() throws Exception {
        // Given
        historyProvider = new TestHistoryProvider();
        AuthUtils.setHistoryProvider(historyProvider);

        List<HttpMessage> msgs =
                DiagnosticDataLoader.loadTestData(
                        this.getResourcePath("internal/ctflearn.diags").toFile());

        // When
        msgs.forEach(
                msg -> {
                    PassiveScanData helper2 = new PassiveScanData(msg);
                    rule.setHelper(helper2);
                    rule.setPassiveScanActions(actions);
                    rule.scanHttpResponseReceive(msg, 1, null);
                });

        // Then
        assertThat(alertsRaised.size(), is(equalTo(3)));
        assertThat(alertsRaised.get(0).getUri(), is(equalTo("https://example0/login")));
        assertThat(alertsRaised.get(0).getMethod(), is(equalTo("GET")));
        assertThat(alertsRaised.get(0).getEvidence(), is(equalTo("session")));
        assertThat(alertsRaised.get(0).getOtherInfo(), is(equalTo("cookie:session")));
        assertThat(alertsRaised.get(0).getConfidence(), is(equalTo(Alert.CONFIDENCE_MEDIUM)));
        assertThat(alertsRaised.get(1).getUri(), is(equalTo("https://example0/dashboard")));
        assertThat(alertsRaised.get(1).getMethod(), is(equalTo("GET")));
        assertThat(alertsRaised.get(1).getEvidence(), is(equalTo("session")));
        assertThat(alertsRaised.get(1).getOtherInfo(), is(equalTo("cookie:session")));
        assertThat(alertsRaised.get(1).getConfidence(), is(equalTo(Alert.CONFIDENCE_MEDIUM)));
        assertThat(alertsRaised.get(2).getUri(), is(equalTo("https://example0/login")));
        assertThat(alertsRaised.get(2).getMethod(), is(equalTo("GET")));
        assertThat(alertsRaised.get(2).getEvidence(), is(equalTo("session")));
        assertThat(alertsRaised.get(2).getOtherInfo(), is(equalTo("cookie:session")));
        assertThat(alertsRaised.get(2).getConfidence(), is(equalTo(Alert.CONFIDENCE_MEDIUM)));
    }

    @Test
    void shouldDetectDefthewebSession() throws Exception {
        // Given
        historyProvider = new TestHistoryProvider();
        AuthUtils.setHistoryProvider(historyProvider);

        List<HttpMessage> msgs =
                DiagnosticDataLoader.loadTestData(
                        this.getResourcePath("internal/deftheweb.diags").toFile());

        // When
        msgs.forEach(
                msg -> {
                    PassiveScanData helper2 = new PassiveScanData(msg);
                    rule.setHelper(helper2);
                    rule.setPassiveScanActions(actions);
                    rule.scanHttpResponseReceive(msg, 1, null);
                });

        // Then
        assertThat(alertsRaised.size(), is(equalTo(1)));
        assertThat(alertsRaised.get(0).getUri(), is(equalTo("https://example0/auth")));
        assertThat(alertsRaised.get(0).getEvidence(), is(equalTo("PHPSESSID")));
        assertThat(alertsRaised.get(0).getOtherInfo(), is(equalTo("cookie:PHPSESSID")));
        assertThat(alertsRaised.get(0).getConfidence(), is(equalTo(Alert.CONFIDENCE_MEDIUM)));
    }

    @Test
    void shouldDetectGinnjuiceSession() throws Exception {
        // Given
        historyProvider = new TestHistoryProvider();
        AuthUtils.setHistoryProvider(historyProvider);

        List<HttpMessage> msgs =
                DiagnosticDataLoader.loadTestData(
                        this.getResourcePath("internal/ginnjuice.diags").toFile());

        // When
        msgs.forEach(
                msg -> {
                    PassiveScanData helper2 = new PassiveScanData(msg);
                    rule.setHelper(helper2);
                    rule.setPassiveScanActions(actions);
                    rule.scanHttpResponseReceive(msg, 1, null);
                });

        // Then
        assertThat(alertsRaised.size(), is(equalTo(1)));
        assertThat(alertsRaised.get(0).getUri(), is(equalTo("https://example0/login")));
        assertThat(alertsRaised.get(0).getEvidence(), is(equalTo("session")));
        assertThat(
                alertsRaised.get(0).getOtherInfo(),
                is(equalTo("cookie:session\ncookie:AWSALBCORS\ncookie:AWSALB")));
        assertThat(alertsRaised.get(0).getConfidence(), is(equalTo(Alert.CONFIDENCE_MEDIUM)));
    }

    @Test
    void shouldDetectInfosecexSession() throws Exception {
        // Given
        historyProvider = new TestHistoryProvider();
        AuthUtils.setHistoryProvider(historyProvider);

        List<HttpMessage> msgs =
                DiagnosticDataLoader.loadTestData(
                        this.getResourcePath("internal/infosecex.diags").toFile());

        // When
        msgs.forEach(
                msg -> {
                    PassiveScanData helper2 = new PassiveScanData(msg);
                    rule.setHelper(helper2);
                    rule.setPassiveScanActions(actions);
                    rule.scanHttpResponseReceive(msg, 1, null);
                });

        // Then
        assertThat(alertsRaised.size(), is(equalTo(3)));
        assertThat(alertsRaised.get(0).getUri(), is(equalTo("https://example0/sign_in")));
        assertThat(alertsRaised.get(0).getEvidence(), is(equalTo("_mastodon_session")));
        assertThat(alertsRaised.get(0).getOtherInfo(), is(equalTo("cookie:_mastodon_session")));
        assertThat(alertsRaised.get(0).getConfidence(), is(equalTo(Alert.CONFIDENCE_MEDIUM)));

        assertThat(alertsRaised.get(1).getUri(), is(equalTo("https://example0/")));
        assertThat(alertsRaised.get(1).getEvidence(), is(equalTo("_session_id")));
        assertThat(
                alertsRaised.get(1).getOtherInfo(),
                is(equalTo("cookie:_session_id\ncookie:_mastodon_session")));
        assertThat(alertsRaised.get(1).getConfidence(), is(equalTo(Alert.CONFIDENCE_MEDIUM)));

        assertThat(alertsRaised.get(2).getUri(), is(equalTo("https://example0/")));
        assertThat(alertsRaised.get(2).getEvidence(), is(equalTo("_session_id")));
        assertThat(
                alertsRaised.get(2).getOtherInfo(),
                is(equalTo("cookie:_session_id\ncookie:_mastodon_session")));
        assertThat(alertsRaised.get(2).getConfidence(), is(equalTo(Alert.CONFIDENCE_MEDIUM)));
    }

    @Test
    void shouldFindTokenWhenOneIsPreviouslyUnknown() throws Exception {
        // Given
        Constant.messages = mock(I18N.class);
        model = mock(Model.class);
        extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));

        historyProvider = new TestHistoryProvider();
        AuthUtils.setHistoryProvider(historyProvider);

        Control.initSingletonForTesting(model, extensionLoader);
        Model.setSingletonForTesting(model);

        Session session = mock(Session.class);
        given(session.getContextsForUrl(anyString())).willReturn(Arrays.asList());
        given(model.getSession()).willReturn(session);

        String cookie = "67890123456789012345";
        String jwtValue = "bearer 677890123456789012345-677890123456789012345";
        String jwt = "{\"jwt\":\"%s\"}".formatted(jwtValue);
        HttpMessage msg =
                new HttpMessage(
                        new HttpRequestHeader(
                                """
                                POST / HTTP/1.1\r
                                Header1: Value1\r
                                Header2: Value2\r
                                cookie: jsessionid=%s\r
                                Host: example.com\r\n\r\n"""),
                        new HttpRequestBody(
                                "{\"username\":\"FakeUserName@example.com\",\"password\":\"F4keP4ssw0rd\"}"),
                        new HttpResponseHeader(
                                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n"),
                        new HttpResponseBody(jwt));

        HttpMessage msg2 =
                new HttpMessage(
                        new HttpRequestHeader(
                                """
                                GET /home HTTP/1.1\r
                                Header1: Value1\r
                                Header2: Value2\r
                                cookie: jsessionid=%s\r
                                x-auth-token: %s\r
                                Host: example.com\r\n\r\n"""
                                        .formatted(cookie, jwtValue)),
                        new HttpRequestBody(""),
                        new HttpResponseHeader("HTTP/1.1 200 OK\r\n"),
                        new HttpResponseBody("<html></html>"));

        List<HttpMessage> msgs = List.of(msg, msg2);
        historyProvider.addAuthMessageToHistory(msg);
        historyProvider.addAuthMessageToHistory(msg2);
        AuthUtils.recordSessionToken(
                new SessionToken(SessionToken.COOKIE_SOURCE, "jsessionid", cookie));
        SessionDetectionScanRule rule = this.createScanner();

        // When
        msgs.forEach(
                m -> {
                    PassiveScanData helper = new PassiveScanData(m);
                    rule.setHelper(helper);
                    rule.setPassiveScanActions(actions);
                    rule.scanHttpResponseReceive(m, 1, null);
                });

        // Then
        assertThat(alertsRaised, hasSize(1));
        Alert expected = alertsRaised.get(0);
        assertThat(expected.getParam(), is(equalTo("jwt")));
        assertThat(expected.getOtherInfo(), is(equalTo("json:jwt")));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "Blah",
                "text/css",
                "text/javascript",
                "image/png",
                "image/svg+xml",
                "font/ttf"
            })
    void shouldIgnoreUnknownOrUnwantedContentTypes(String contentType)
            throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/login/ HTTP/1.1");
        msg.getRequestHeader().setHeader(HttpHeader.CONTENT_TYPE, contentType);
        msg.getRequestHeader().setHeader(HttpHeader.REFERER, "https://www.example.com/");
        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                """
                HTTP/1.1 200 OK\r
                Server: Apache-Coyote/1.1\r
                Content-Type: text/html;charset=ISO-8859-1\r
                Content-Length: %s\r\n\r
                """
                        .formatted(msg.getResponseBody().length()));
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised, hasSize(0));
    }
}
