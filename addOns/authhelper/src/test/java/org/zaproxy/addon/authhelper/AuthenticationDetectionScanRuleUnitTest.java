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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.authentication.FormBasedAuthenticationMethodType;
import org.zaproxy.zap.authentication.JsonBasedAuthenticationMethodType;
import org.zaproxy.zap.extension.anticsrf.AntiCsrfToken;
import org.zaproxy.zap.extension.anticsrf.ExtensionAntiCSRF;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

class AuthenticationDetectionScanRuleUnitTest
        extends PassiveScannerTest<AuthenticationDetectionScanRule> {

    private ExtensionAuthhelper extAuth;
    private ExtensionLoader extensionLoader;

    @Mock(strictness = org.mockito.Mock.Strictness.LENIENT)
    Model model;

    @Mock(strictness = org.mockito.Mock.Strictness.LENIENT)
    Session session;

    @BeforeEach
    @Override
    public void setUp() throws Exception {
        super.setUp();

        given(model.getSession()).willReturn(session);
        extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        extAuth = new ExtensionAuthhelper();
        extAuth.initModel(model);
        given(extensionLoader.getExtension(ExtensionAuthhelper.class)).willReturn(extAuth);

        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);
    }

    @Override
    protected AuthenticationDetectionScanRule createScanner() {
        return new AuthenticationDetectionScanRule();
    }

    @Test
    void shouldIgnoreSimpleGet() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");
        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "X-Frame-Options: DENY\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldAlertOnGetWithAuthParams() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(
                "GET http://www.example.com/test/?username=test&password=pass123 HTTP/1.1");
        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getName(), equalTo("Authentication Request Identified"));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(1));
        assertThat(alertsRaised.get(0).getParam(), equalTo("username"));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo("password"));
        assertThat(
                alertsRaised.get(0).getOtherInfo(),
                equalTo("userParam=username\nuserValue=test\npasswordParam=password"));
    }

    @Test
    void shouldIgnoreRegistrationUrl() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(
                "GET http://www.example.com/register/?username=test&password=pass123 HTTP/1.1");
        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldIgnoreRequestWithNoUsername() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(
                "GET http://www.example.com/register/?blah=test&password=test HTTP/1.1");
        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldIgnoreRequestWithNoPassword() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(
                "GET http://www.example.com/register/?username=test&title=unknown HTTP/1.1");
        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldAlertOnPostWithFormAuthParams() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("POST http://www.example.com/login/ HTTP/1.1");
        msg.getRequestHeader()
                .setHeader(HttpHeader.CONTENT_TYPE, HttpHeader.FORM_URLENCODED_CONTENT_TYPE);
        msg.getRequestHeader().setHeader(HttpHeader.REFERER, "http://www.example.com/");
        msg.setRequestBody("user=test2&pwd=pass123");
        msg.getRequestHeader().setContentLength(msg.getRequestBody().length());
        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getName(), equalTo("Authentication Request Identified"));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(3));
        assertThat(alertsRaised.get(0).getParam(), equalTo("user"));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo("pwd"));
        assertThat(
                alertsRaised.get(0).getOtherInfo(),
                equalTo(
                        "userParam=user\nuserValue=test2\npasswordParam=pwd\nreferer=http://www.example.com/"));
    }

    @Test
    void shouldAlertWithCsrfTokensOnPostWithFormAuthParams() throws HttpMalformedHeaderException {
        // Given
        ExtensionAntiCSRF extAcsrf =
                mock(ExtensionAntiCSRF.class, withSettings().strictness(Strictness.LENIENT));
        List<AntiCsrfToken> tokenList = new ArrayList<>();
        tokenList.add(new AntiCsrfToken(null, "acsrf1", null, 0));
        tokenList.add(new AntiCsrfToken(null, "acsrf2", null, 0));
        given(extAcsrf.getTokens(any())).willReturn(tokenList);
        given(extensionLoader.getExtension(ExtensionAntiCSRF.class)).willReturn(extAcsrf);

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("POST http://www.example.com/login/ HTTP/1.1");
        msg.getRequestHeader()
                .setHeader(HttpHeader.CONTENT_TYPE, HttpHeader.FORM_URLENCODED_CONTENT_TYPE);
        msg.getRequestHeader().setHeader(HttpHeader.REFERER, "http://www.example.com/");
        msg.setRequestBody("user=test2&pwd=pass123");
        msg.getRequestHeader().setContentLength(msg.getRequestBody().length());
        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getName(), equalTo("Authentication Request Identified"));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(3));
        assertThat(alertsRaised.get(0).getParam(), equalTo("user"));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo("pwd"));
        assertThat(
                alertsRaised.get(0).getOtherInfo(),
                equalTo(
                        "userParam=user\nuserValue=test2\npasswordParam=pwd\nreferer=http://www.example.com/\ncsrfToken=acsrf1\ncsrfToken=acsrf2"));
    }

    @Test
    void shouldAlertOnPostWithJsonAuthParams() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("POST http://www.example.com/login/ HTTP/1.1");
        msg.getRequestHeader().setHeader(HttpHeader.CONTENT_TYPE, HttpHeader.JSON_CONTENT_TYPE);
        msg.setRequestBody("{\"email\":\"test@test.com\",\"password\":\"test123\"}");
        msg.getRequestHeader().setContentLength(msg.getRequestBody().length());
        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getName(), equalTo("Authentication Request Identified"));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(3));
        assertThat(alertsRaised.get(0).getParam(), equalTo("email"));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo("password"));
        assertThat(
                alertsRaised.get(0).getOtherInfo(),
                equalTo("userParam=email\nuserValue=test@test.com\npasswordParam=password"));
    }

    @Test
    void shouldAlertOnPostWithDeeperJsonAuthParams() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("POST http://www.example.com/login/ HTTP/1.1");
        msg.getRequestHeader().setHeader(HttpHeader.CONTENT_TYPE, HttpHeader.JSON_CONTENT_TYPE);
        msg.setRequestBody(
                "{\"authentication\":{\"test\":{ \"email\":\"test@test.com\",\"password\":\"test123\"}}}");
        msg.getRequestHeader().setContentLength(msg.getRequestBody().length());
        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getName(), equalTo("Authentication Request Identified"));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(3));
        assertThat(alertsRaised.get(0).getParam(), equalTo("authentication.test.email"));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo("authentication.test.password"));
        assertThat(
                alertsRaised.get(0).getOtherInfo(),
                equalTo(
                        "userParam=authentication.test.email\nuserValue=test@test.com\npasswordParam=authentication.test.password"));
    }

    @Test
    void shouldIgnoreInvalidJson() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("POST http://www.example.com/login/ HTTP/1.1");
        msg.getRequestHeader().setHeader(HttpHeader.CONTENT_TYPE, HttpHeader.JSON_CONTENT_TYPE);
        msg.setRequestBody("{\"email\":\"test@test.com\",\"password\":\"test123\"");
        msg.getRequestHeader().setContentLength(msg.getRequestBody().length());
        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldIgnoreUnknownContentType() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("POST http://www.example.com/login/ HTTP/1.1");
        msg.getRequestHeader().setHeader(HttpHeader.CONTENT_TYPE, "Blah");
        msg.getRequestHeader().setHeader(HttpHeader.REFERER, "http://www.example.com/");
        msg.setRequestBody("user=test2&pwd=pass123");
        msg.getRequestHeader().setContentLength(msg.getRequestBody().length());
        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldSetUpPostBasedAuth() throws HttpMalformedHeaderException {
        // Given
        List<Context> clist = new ArrayList<>();
        Context context = new Context(session, 1);
        AutoDetectAuthenticationMethodType autoAuthType = new AutoDetectAuthenticationMethodType();
        context.setAuthenticationMethod(autoAuthType.createAuthenticationMethod(context.getId()));
        clist.add(context);
        when(session.getContextsForUrl(anyString())).thenReturn(clist);

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("POST http://www.example.com/login/ HTTP/1.1");
        msg.getRequestHeader()
                .setHeader(HttpHeader.CONTENT_TYPE, HttpHeader.FORM_URLENCODED_CONTENT_TYPE);
        msg.getRequestHeader().setHeader(HttpHeader.REFERER, "http://www.example.com/redirect/");
        msg.setRequestBody("user=test2&pwd=pass123");
        msg.getRequestHeader().setContentLength(msg.getRequestBody().length());
        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        ZapXmlConfiguration conf = new ZapXmlConfiguration();
        // When
        scanHttpResponseReceive(msg);
        context.getAuthenticationMethod()
                .getType()
                .exportData(conf, context.getAuthenticationMethod());
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(
                context.getAuthenticationMethod().getType().getClass(),
                equalTo(FormBasedAuthenticationMethodType.class));

        assertThat(
                conf.getString("context.authentication.form.loginurl"),
                equalTo("http://www.example.com/login/"));
        assertThat(
                conf.getString("context.authentication.form.loginpageurl"),
                equalTo("http://www.example.com/redirect/"));
        assertThat(
                conf.getString("context.authentication.form.loginbody"),
                equalTo("user={%username%}&pwd={%password%}"));
    }

    @Test
    void shouldSetUpJsonBasedAuth() throws HttpMalformedHeaderException {
        // Given
        List<Context> clist = new ArrayList<>();
        Context context = new Context(session, 1);
        AutoDetectAuthenticationMethodType autoAuthType = new AutoDetectAuthenticationMethodType();
        context.setAuthenticationMethod(autoAuthType.createAuthenticationMethod(context.getId()));
        clist.add(context);
        when(session.getContextsForUrl(anyString())).thenReturn(clist);

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("POST http://www.example.com/login/ HTTP/1.1");
        msg.getRequestHeader().setHeader(HttpHeader.REFERER, "http://www.example.com/redirect/");
        msg.getRequestHeader().setHeader(HttpHeader.CONTENT_TYPE, HttpHeader.JSON_CONTENT_TYPE);
        msg.setRequestBody(
                "{\"authentication\":{\"test\":{ \"email\":\"test@test.com\",\"password\":\"test123\"}}}");
        msg.getRequestHeader().setContentLength(msg.getRequestBody().length());
        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        ZapXmlConfiguration conf = new ZapXmlConfiguration();
        // When
        scanHttpResponseReceive(msg);
        context.getAuthenticationMethod()
                .getType()
                .exportData(conf, context.getAuthenticationMethod());
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(
                context.getAuthenticationMethod().getType().getClass(),
                equalTo(JsonBasedAuthenticationMethodType.class));

        assertThat(
                conf.getString("context.authentication.form.loginurl"),
                equalTo("http://www.example.com/login/"));
        assertThat(
                conf.getString("context.authentication.form.loginpageurl"),
                equalTo("http://www.example.com/redirect/"));
        assertThat(
                conf.getString("context.authentication.form.loginbody"),
                equalTo(
                        "{\"authentication\":{\"test\":{ \"email\":\"{%username%}\",\"password\":\"{%password%}\"}}}"));
    }
}
