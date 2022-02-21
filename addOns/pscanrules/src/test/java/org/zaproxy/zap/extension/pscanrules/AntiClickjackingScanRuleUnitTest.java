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
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;

import java.util.Map;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;

class AntiClickjackingScanRuleUnitTest extends PassiveScannerTest<AntiClickjackingScanRule> {

    private static final String BASE_RESOURCE_KEY = "pscanrules.anticlickjacking.";
    private static final String NAME_HEADER_NOT_SET = BASE_RESOURCE_KEY + "missing.name";
    private static final String NAME_MULTIPLE_HEADERS = BASE_RESOURCE_KEY + "multiple.header.name";
    private static final String NAME_DEFINED_IN_META = BASE_RESOURCE_KEY + "compliance.meta.name";
    private static final String NAME_MALFORMED =
            BASE_RESOURCE_KEY + "compliance.malformed.setting.name";

    @Override
    protected AntiClickjackingScanRule createScanner() {
        return new AntiClickjackingScanRule();
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        int cwe = rule.getCweId();
        int wasc = rule.getWascId();
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(cwe, is(equalTo(1021)));
        assertThat(wasc, is(equalTo(15)));
        assertThat(tags.size(), is(equalTo(3)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.WSTG_V42_CLNT_09_CLICKJACK.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getValue())));
        assertThat(
                tags.get(CommonAlertTag.WSTG_V42_CLNT_09_CLICKJACK.getTag()),
                is(equalTo(CommonAlertTag.WSTG_V42_CLNT_09_CLICKJACK.getValue())));
    }

    @Test
    void xframeOptionsDeny() throws HttpMalformedHeaderException {
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
        given(passiveScanData.isClientError(any())).willReturn(false);
        given(passiveScanData.isServerError(any())).willReturn(false);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void xframeOptionsDenyLc() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");
        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "X-Frame-Options: deny\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        given(passiveScanData.isClientError(any())).willReturn(false);
        given(passiveScanData.isServerError(any())).willReturn(false);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void xframeOptionsDenyMc() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");
        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "X-Frame-Options: dEnY\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        given(passiveScanData.isClientError(any())).willReturn(false);
        given(passiveScanData.isServerError(any())).willReturn(false);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void xframeOptionsSameOrigin() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");
        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "X-Frame-Options: SAMEORIGIN\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        given(passiveScanData.isClientError(any())).willReturn(false);
        given(passiveScanData.isServerError(any())).willReturn(false);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void xframeOptionsAllowFrom() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");
        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "X-Frame-Options: ALLOW-FROM https://www.anotherdomain.com/\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        given(passiveScanData.isClientError(any())).willReturn(false);
        given(passiveScanData.isServerError(any())).willReturn(false);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
    }

    @Test
    void noXframeOptions() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");
        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        given(passiveScanData.isClientError(any())).willReturn(false);
        given(passiveScanData.isServerError(any())).willReturn(false);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0), hasNameLoadedWithKey(NAME_HEADER_NOT_SET));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_MEDIUM));
        assertThat(alertsRaised.get(0).getParam(), equalTo(HttpHeader.X_FRAME_OPTION));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo(""));
        assertThat(alertsRaised.get(0).getAlertRef(), equalTo("10020-1"));
    }

    @Test
    void noXframeOptionsErrorLow() throws HttpMalformedHeaderException {
        // Given
        rule.setAlertThreshold(AlertThreshold.LOW);
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");
        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 401 Unauthorized\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        given(passiveScanData.isClientError(any())).willReturn(true);
        given(passiveScanData.isServerError(any())).willReturn(false);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0), hasNameLoadedWithKey(NAME_HEADER_NOT_SET));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_MEDIUM));
        assertThat(alertsRaised.get(0).getParam(), equalTo(HttpHeader.X_FRAME_OPTION));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo(""));
        assertThat(alertsRaised.get(0).getAlertRef(), equalTo("10020-1"));
    }

    @Test
    void noXframeOptionsErrorMed() throws HttpMalformedHeaderException {
        // Given
        rule.setAlertThreshold(AlertThreshold.MEDIUM);
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");
        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 401 Unauthorized\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        given(passiveScanData.isClientError(any())).willReturn(true);
        given(passiveScanData.isServerError(any())).willReturn(false);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void noXframeOptionsErrorHigh() throws HttpMalformedHeaderException {
        // Given
        rule.setAlertThreshold(AlertThreshold.HIGH);
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");
        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 401 Unauthorized\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        given(passiveScanData.isClientError(any())).willReturn(true);
        given(passiveScanData.isServerError(any())).willReturn(false);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void noXframeOptionsPlainTextLow() throws HttpMalformedHeaderException {
        // Given
        rule.setAlertThreshold(AlertThreshold.LOW);
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");
        msg.setResponseBody("Blah");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Type: text/plain;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        given(passiveScanData.isClientError(any())).willReturn(false);
        given(passiveScanData.isServerError(any())).willReturn(false);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0), hasNameLoadedWithKey(NAME_HEADER_NOT_SET));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_MEDIUM));
        assertThat(alertsRaised.get(0).getParam(), equalTo(HttpHeader.X_FRAME_OPTION));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo(""));
        assertThat(alertsRaised.get(0).getAlertRef(), equalTo("10020-1"));
    }

    @Test
    void noXframeOptionsPlainTextMed() throws HttpMalformedHeaderException {
        // Given
        rule.setAlertThreshold(AlertThreshold.MEDIUM);
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");
        msg.setResponseBody("blah");
        msg.setResponseHeader(
                "HTTP/1.1 401 Unauthorized\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Type: text/plain;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        given(passiveScanData.isClientError(any())).willReturn(true);
        given(passiveScanData.isServerError(any())).willReturn(false);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void noXframeOptionsPlainTextHigh() throws HttpMalformedHeaderException {
        // Given
        rule.setAlertThreshold(AlertThreshold.HIGH);
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");
        msg.setResponseBody("blah");
        msg.setResponseHeader(
                "HTTP/1.1 401 Unauthorized\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Type: text/plain;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        given(passiveScanData.isClientError(any())).willReturn(true);
        given(passiveScanData.isServerError(any())).willReturn(false);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void multipleXframeOptions() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");
        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "X-Frame-Options: DENY\r\n"
                        + "X-Frame-Options: SAMEORIGIN\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        given(passiveScanData.isClientError(any())).willReturn(false);
        given(passiveScanData.isServerError(any())).willReturn(false);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0), hasNameLoadedWithKey(NAME_MULTIPLE_HEADERS));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_MEDIUM));
        assertThat(alertsRaised.get(0).getParam(), equalTo(HttpHeader.X_FRAME_OPTION));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo(""));
        assertThat(alertsRaised.get(0).getAlertRef(), equalTo("10020-2"));
    }

    @Test
    void xframeOptionsViaMetaTag() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");
        msg.setResponseBody(
                "<html>" + "<meta http-equiv=\"X-Frame-Options\" content=\"DENY\">" + "</html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        given(passiveScanData.isClientError(any())).willReturn(false);
        given(passiveScanData.isServerError(any())).willReturn(false);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(2));
        assertThat(alertsRaised.get(0), hasNameLoadedWithKey(NAME_HEADER_NOT_SET));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_MEDIUM));
        assertThat(alertsRaised.get(0).getParam(), equalTo(HttpHeader.X_FRAME_OPTION));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo(""));
        assertThat(alertsRaised.get(1), hasNameLoadedWithKey(NAME_DEFINED_IN_META));
        assertThat(alertsRaised.get(1).getRisk(), equalTo(Alert.RISK_MEDIUM));
        assertThat(alertsRaised.get(1).getParam(), equalTo(HttpHeader.X_FRAME_OPTION));
        assertThat(
                alertsRaised.get(1).getEvidence(),
                equalTo("<meta http-equiv=\"X-Frame-Options\" content=\"DENY\">"));
        assertThat(alertsRaised.get(0).getAlertRef(), equalTo("10020-1"));
    }

    @Test
    void xframeOptionsViaMetaTagAndHeader() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");
        msg.setResponseBody(
                "<html>" + "<meta http-equiv=\"X-Frame-Options\" content=\"DENY\">" + "</html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "X-Frame-Options: DENY\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        given(passiveScanData.isClientError(any())).willReturn(false);
        given(passiveScanData.isServerError(any())).willReturn(false);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0), hasNameLoadedWithKey(NAME_DEFINED_IN_META));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_MEDIUM));
        assertThat(alertsRaised.get(0).getParam(), equalTo(HttpHeader.X_FRAME_OPTION));
        assertThat(
                alertsRaised.get(0).getEvidence(),
                equalTo("<meta http-equiv=\"X-Frame-Options\" content=\"DENY\">"));
        assertThat(alertsRaised.get(0).getAlertRef(), equalTo("10020-3"));
    }

    @Test
    void malformedXframeOptions() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");
        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "X-Frame-Options: STUFF\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        given(passiveScanData.isClientError(any())).willReturn(false);
        given(passiveScanData.isServerError(any())).willReturn(false);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0), hasNameLoadedWithKey(NAME_MALFORMED));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_MEDIUM));
        assertThat(alertsRaised.get(0).getParam(), equalTo(HttpHeader.X_FRAME_OPTION));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo("STUFF"));
        assertThat(alertsRaised.get(0).getAlertRef(), equalTo("10020-4"));
    }

    @Test
    void cspNoFaNoXframeOptions() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");
        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Security-Policy: default-src 'self';\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        given(passiveScanData.isClientError(any())).willReturn(false);
        given(passiveScanData.isServerError(any())).willReturn(false);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0), hasNameLoadedWithKey(NAME_HEADER_NOT_SET));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_MEDIUM));
        assertThat(alertsRaised.get(0).getParam(), equalTo(HttpHeader.X_FRAME_OPTION));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo(""));
        assertThat(alertsRaised.get(0).getAlertRef(), equalTo("10020-1"));
    }

    @Test
    void cspWithFaNoXframeOptions() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");
        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Security-Policy: default-src 'self'; frame-ancestors 'none'\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        given(passiveScanData.isClientError(any())).willReturn(false);
        given(passiveScanData.isServerError(any())).willReturn(false);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void cspWithFaWithXframeOptions() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");
        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Security-Policy: default-src 'self'; frame-ancestors 'none'\r\n"
                        + "X-Frame-Options: DENY\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        given(passiveScanData.isClientError(any())).willReturn(false);
        given(passiveScanData.isServerError(any())).willReturn(false);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void cspWithFaWithBadXframeOptionsLow() throws HttpMalformedHeaderException {
        // Given
        rule.setAlertThreshold(AlertThreshold.LOW);
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");
        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Security-Policy: default-src 'self'; frame-ancestors 'none'\r\n"
                        + "X-Frame-Options: BAD\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        given(passiveScanData.isClientError(any())).willReturn(false);
        given(passiveScanData.isServerError(any())).willReturn(false);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0), hasNameLoadedWithKey(NAME_MALFORMED));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_LOW));
        assertThat(alertsRaised.get(0).getParam(), equalTo(HttpHeader.X_FRAME_OPTION));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo("BAD"));
        assertThat(alertsRaised.get(0).getAlertRef(), equalTo("10020-4"));
    }

    @Test
    void cspWithFaWithBadXframeOptionsMedium() throws HttpMalformedHeaderException {
        // Given
        rule.setAlertThreshold(AlertThreshold.MEDIUM);
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");
        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Security-Policy: default-src 'self'; frame-ancestors 'none'\r\n"
                        + "X-Frame-Options: BAD\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        given(passiveScanData.isClientError(any())).willReturn(false);
        given(passiveScanData.isServerError(any())).willReturn(false);
        // When
        scanHttpResponseReceive(msg);
        // THen
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void cspWithFaWithBadXframeOptionsHigh() throws HttpMalformedHeaderException {
        // Given
        rule.setAlertThreshold(AlertThreshold.HIGH);
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");
        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Security-Policy: default-src 'self'; frame-ancestors 'none'\r\n"
                        + "X-Frame-Options: BAD\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        given(passiveScanData.isClientError(any())).willReturn(false);
        given(passiveScanData.isServerError(any())).willReturn(false);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }
}
