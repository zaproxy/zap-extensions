/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP Development Team
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
package org.zaproxy.zap.extension.pscanrules;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

import java.io.IOException;
import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.extension.encoder.Base64;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpResponseHeader;

public class InsecureAuthenticationScanRuleUnitTest
        extends PassiveScannerTest<InsecureAuthenticationScanRule> {

    private static final String BASE_RESOURCE_KEY = "pscanrules.authenticationcredentialscaptured.";
    private static final String ALERT_NAME = BASE_RESOURCE_KEY + "name";
    private static final String BASIC_AUTH_KEY = BASE_RESOURCE_KEY + "alert.basicauth.extrainfo";
    private static final String DIGEST_AUTH_KEY = BASE_RESOURCE_KEY + "alert.digestauth.extrainfo";
    private static final String AUTHORIZATION_BASIC = "Basic";
    private static final String AUTHORIZATION_DIGEST = "Digest";
    private static final String INSECURE_RESPONSE = "pscanrules.insecureauthentication.name";

    private final String user = "admin";
    private final String pass = "admin";

    @Override
    protected InsecureAuthenticationScanRule createScanner() {
        return new InsecureAuthenticationScanRule();
    }

    @Test
    public void shouldBeSecureIfHttpUsedWithSsl() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
        // When
        scanHttpRequestSend(msg);
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void shouldRaiseAlertIfBasicAuthenticationWithNoSsl()
            throws NullPointerException, IOException {
        // Given
        String userAndPass = user + ":" + pass;
        HttpMessage msg = new HttpMessage();
        HttpRequestHeader requestHeader =
                new HttpRequestHeader(
                        HttpRequestHeader.POST,
                        new URI("http://www.example.com", true),
                        HttpRequestHeader.HTTP11);
        requestHeader.addHeader(
                HttpHeader.AUTHORIZATION,
                AUTHORIZATION_BASIC
                        + " "
                        + Base64.encodeBytes(userAndPass.getBytes(), Base64.DONT_GUNZIP));
        msg.setRequestHeader(requestHeader);
        // When
        scanHttpRequestSend(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0), containsNameLoadedWithKey(ALERT_NAME));
        assertThat(
                alertsRaised.get(0),
                containsOtherInfoLoadedWithKey(
                        BASIC_AUTH_KEY,
                        HttpRequestHeader.POST,
                        requestHeader.getURI().getURI(),
                        AUTHORIZATION_BASIC,
                        user,
                        pass));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_HIGH));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
        assertThat(alertsRaised.get(0).getCweId(), equalTo(287));
        assertThat(alertsRaised.get(0).getWascId(), equalTo(1));
    }

    @Test
    public void shouldRaiseAlertIfBasicAuthenticationOnlyUserWithNoSsl()
            throws NullPointerException, IOException {
        // Given
        HttpMessage msg = new HttpMessage();
        HttpRequestHeader requestHeader =
                new HttpRequestHeader(
                        HttpRequestHeader.POST,
                        new URI("http://www.example.com", true),
                        HttpRequestHeader.HTTP11);
        requestHeader.addHeader(
                HttpHeader.AUTHORIZATION,
                AUTHORIZATION_BASIC
                        + " "
                        + Base64.encodeBytes(user.getBytes(), Base64.DONT_GUNZIP));
        msg.setRequestHeader(requestHeader);
        // When
        scanHttpRequestSend(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0), containsNameLoadedWithKey(ALERT_NAME));
        assertThat(
                alertsRaised.get(0),
                containsOtherInfoLoadedWithKey(
                        BASIC_AUTH_KEY,
                        HttpRequestHeader.POST,
                        requestHeader.getURI().getURI(),
                        AUTHORIZATION_BASIC,
                        user,
                        null));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_MEDIUM));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
        assertThat(alertsRaised.get(0).getCweId(), equalTo(287));
        assertThat(alertsRaised.get(0).getWascId(), equalTo(1));
    }

    @Test
    public void shouldRaiseAlertIfBasicAuthenticationResponseWithNoSsl()
            throws NullPointerException, IOException {
        // Given
        HttpMessage msg = new HttpMessage();
        HttpRequestHeader requestHeader =
                new HttpRequestHeader(
                        HttpRequestHeader.POST,
                        new URI("http://www.example.com", true),
                        HttpRequestHeader.HTTP11);
        msg.setRequestHeader(requestHeader);
        HttpResponseHeader responsHeader = new HttpResponseHeader();
        responsHeader.addHeader(
                HttpHeader.WWW_AUTHENTICATE, AUTHORIZATION_BASIC + " realm=\"Private\"");
        msg.setResponseHeader(responsHeader);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0), containsNameLoadedWithKey(INSECURE_RESPONSE));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_MEDIUM));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
        assertThat(alertsRaised.get(0).getCweId(), equalTo(326));
        assertThat(alertsRaised.get(0).getWascId(), equalTo(4));
    }

    @Test
    public void shouldRaiseAlertIfDigestAuthenticationWithNoSsl()
            throws NullPointerException, IOException {
        // Given
        String digestValue = "username=\"" + user + "\", realm=\"members only\"";
        HttpMessage msg = new HttpMessage();
        HttpRequestHeader requestHeader =
                new HttpRequestHeader(
                        HttpRequestHeader.POST,
                        new URI("http://www.example.com", true),
                        HttpRequestHeader.HTTP11);
        requestHeader.addHeader(HttpHeader.AUTHORIZATION, AUTHORIZATION_DIGEST + " " + digestValue);
        msg.setRequestHeader(requestHeader);
        // When
        scanHttpRequestSend(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0), containsNameLoadedWithKey(ALERT_NAME));
        assertThat(
                alertsRaised.get(0),
                containsOtherInfoLoadedWithKey(
                        DIGEST_AUTH_KEY,
                        HttpRequestHeader.POST,
                        requestHeader.getURI().getURI(),
                        AUTHORIZATION_DIGEST,
                        user,
                        digestValue));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_MEDIUM));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
        assertThat(alertsRaised.get(0).getCweId(), equalTo(287));
        assertThat(alertsRaised.get(0).getWascId(), equalTo(1));
    }
}
