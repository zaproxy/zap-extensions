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

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.notNullValue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.withSettings;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
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

    private List<HttpMessage> history;
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
        assertThat(alertsRaised.get(0).getEvidence(), is(equalTo("sanitizedtoken0")));
        assertThat(alertsRaised.get(0).getOtherInfo(), is(equalTo("\ncookie:JSESSIONID")));
        assertThat(alertsRaised.get(0).getConfidence(), is(equalTo(Alert.CONFIDENCE_MEDIUM)));
    }

    @Test
    void shouldDetectCtflearnSession() throws Exception {
        // Given
        history = new ArrayList<>();
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
        assertThat(alertsRaised.get(0).getEvidence(), is(equalTo("sanitizedtoken17")));
        assertThat(alertsRaised.get(0).getOtherInfo(), is(equalTo("\ncookie:session")));
        assertThat(alertsRaised.get(0).getConfidence(), is(equalTo(Alert.CONFIDENCE_MEDIUM)));
        assertThat(alertsRaised.get(1).getUri(), is(equalTo("https://example0/dashboard")));
        assertThat(alertsRaised.get(1).getMethod(), is(equalTo("GET")));
        assertThat(alertsRaised.get(1).getEvidence(), is(equalTo("sanitizedtoken25")));
        assertThat(alertsRaised.get(1).getOtherInfo(), is(equalTo("\ncookie:session")));
        assertThat(alertsRaised.get(1).getConfidence(), is(equalTo(Alert.CONFIDENCE_MEDIUM)));
        assertThat(alertsRaised.get(2).getUri(), is(equalTo("https://example0/login")));
        assertThat(alertsRaised.get(2).getMethod(), is(equalTo("GET")));
        assertThat(alertsRaised.get(2).getEvidence(), is(equalTo("sanitizedtoken25")));
        assertThat(alertsRaised.get(2).getOtherInfo(), is(equalTo("\ncookie:session")));
        assertThat(alertsRaised.get(2).getConfidence(), is(equalTo(Alert.CONFIDENCE_MEDIUM)));
    }

    @Test
    void shouldDetectDefthewebSession() throws Exception {
        // Given
        history = new ArrayList<>();
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
        assertThat(alertsRaised.get(0).getEvidence(), is(equalTo("sanitizedtoken10")));
        assertThat(alertsRaised.get(0).getOtherInfo(), is(equalTo("\ncookie:PHPSESSID")));
        assertThat(alertsRaised.get(0).getConfidence(), is(equalTo(Alert.CONFIDENCE_MEDIUM)));
    }

    @Test
    void shouldDetectGinnjuiceSession() throws Exception {
        // Given
        history = new ArrayList<>();
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
        assertThat(alertsRaised.get(0).getEvidence(), is(equalTo("sanitizedtoken1")));
        assertThat(
                alertsRaised.get(0).getOtherInfo(),
                is(equalTo("\ncookie:session\ncookie:AWSALBCORS\ncookie:AWSALB")));
        assertThat(alertsRaised.get(0).getConfidence(), is(equalTo(Alert.CONFIDENCE_MEDIUM)));
    }

    @Test
    void shouldDetectInfosecexSession() throws Exception {
        // Given
        history = new ArrayList<>();
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
        assertThat(alertsRaised.get(0).getEvidence(), is(equalTo("sanitizedtoken0")));
        assertThat(alertsRaised.get(0).getOtherInfo(), is(equalTo("\ncookie:_mastodon_session")));
        assertThat(alertsRaised.get(0).getConfidence(), is(equalTo(Alert.CONFIDENCE_MEDIUM)));

        assertThat(alertsRaised.get(1).getUri(), is(equalTo("https://example0/")));
        assertThat(alertsRaised.get(1).getEvidence(), is(equalTo("sanitizedtoken5")));
        assertThat(
                alertsRaised.get(1).getOtherInfo(),
                is(equalTo("\ncookie:_session_id\ncookie:_mastodon_session")));
        assertThat(alertsRaised.get(1).getConfidence(), is(equalTo(Alert.CONFIDENCE_MEDIUM)));

        assertThat(alertsRaised.get(2).getUri(), is(equalTo("https://example0/")));
        assertThat(alertsRaised.get(2).getEvidence(), is(equalTo("sanitizedtoken4747")));
        assertThat(
                alertsRaised.get(2).getOtherInfo(),
                is(equalTo("\ncookie:_session_id\ncookie:_mastodon_session")));
        assertThat(alertsRaised.get(2).getConfidence(), is(equalTo(Alert.CONFIDENCE_MEDIUM)));
    }

    class TestHistoryProvider extends HistoryProvider {
        @Override
        public void addAuthMessageToHistory(HttpMessage msg) {
            history.add(msg);
            int id = history.size() - 1;
            HistoryReference href = mock(HistoryReference.class);
            given(href.getHistoryId()).willReturn(id);
            msg.setHistoryRef(href);
        }

        @Override
        public HttpMessage getHttpMessage(int historyId)
                throws HttpMalformedHeaderException, DatabaseException {
            return history.get(historyId);
        }

        @Override
        public int getLastHistoryId() {
            return history.size() - 1;
        }
    }
}
