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
package org.zaproxy.zap.extension.ascanrulesBeta;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import javax.net.ssl.SSLException;
import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.network.HttpSenderContext;
import org.zaproxy.zap.network.HttpSenderImpl;

class HttpOnlySiteScanRuleUnitTest extends ActiveScannerTest<HttpOnlySiteScanRule> {

    @Override
    protected HttpOnlySiteScanRule createScanner() {
        return new HttpOnlySiteScanRule();
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        int cwe = rule.getCweId();
        int wasc = rule.getWascId();
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(cwe, is(equalTo(311)));
        assertThat(wasc, is(equalTo(4)));
        assertThat(tags.size(), is(equalTo(3)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.WSTG_V42_SESS_02_COOKIE_ATTRS.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getValue())));
        assertThat(
                tags.get(CommonAlertTag.WSTG_V42_SESS_02_COOKIE_ATTRS.getTag()),
                is(equalTo(CommonAlertTag.WSTG_V42_SESS_02_COOKIE_ATTRS.getValue())));
    }

    @Test
    @SuppressWarnings("try")
    void shouldNotTryToConnectIfAlreadyHttps() throws Exception {
        try (var senderImpl = new TestHttpSenderImpl()) {
            // Given
            HttpMessage message = getHttpMessage(80);
            message.getRequestHeader().setSecure(true);
            rule.init(message, parent);
            // When
            rule.scan();
            // Then
            assertThat(httpMessagesSent, hasSize(0));
            assertThat(alertsRaised, hasSize(0));
        }
    }

    @ParameterizedTest
    @CsvSource({"-1, -1", "80, -1", "443, -1", "8080, 8080"})
    @SuppressWarnings("try")
    void shouldAccessHttpsWithExpectedPort(int initialPort, int expectedPort) throws Exception {
        try (var senderImpl = new TestHttpSenderImpl()) {
            // Given
            rule.init(getHttpMessage(initialPort), parent);
            // When
            rule.scan();
            // Then
            assertThat(httpMessagesSent, hasSize(1));
            URI uri = httpMessagesSent.get(0).getRequestHeader().getURI();
            assertThat(uri.getScheme(), is(equalTo(HttpHeader.HTTPS)));
            assertThat(uri.getPort(), is(equalTo(expectedPort)));
        }
    }

    @Test
    void shouldRaiseAlertIfNoHttps() throws Exception {
        try (var senderImpl = new TestHttpSenderImpl()) {
            // Given
            rule.init(getHttpMessage(8080), parent);
            senderImpl.throwException(new SSLException("plaintext"));
            // When
            rule.scan();
            // Then
            assertThat(alertsRaised, hasSize(1));
            Alert alert = alertsRaised.get(0);
            HttpMessage alertMessage = alert.getMessage();
            URI uri = alertMessage.getRequestHeader().getURI();
            assertThat(uri.getScheme(), is(equalTo(HttpHeader.HTTPS)));
            assertOtherInfo(alert, "Site has no SSL/TLS support.");
        }
    }

    private static void assertOtherInfo(Alert alert, String otherInfo) {
        assertThat(alert.getOtherInfo(), containsString(otherInfo));
    }

    @Test
    @SuppressWarnings("try")
    void shouldNotRaiseAlertIfResponseOk() throws Exception {
        try (var senderImpl = new TestHttpSenderImpl()) {
            // Given
            rule.init(getHttpMessage(80), parent);
            // When
            rule.scan();
            // Then
            assertThat(alertsRaised, hasSize(0));
            assertThat(httpMessagesSent, hasSize(1));
        }
    }

    @Test
    void shouldReturnExpectedExampleAlert() {
        List<Alert> alerts = rule.getExampleAlerts();

        assertThat(alerts.size(), is(equalTo(1)));

        Alert alert = alerts.get(0);

        Map<String, String> tags = alert.getTags();
        assertThat(tags.size(), is(equalTo(4)));
        assertThat(tags, hasKey("CWE-311"));
        assertThat(tags, hasKey(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()));
        assertThat(tags, hasKey(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()));
        assertThat(tags, hasKey(CommonAlertTag.WSTG_V42_SESS_02_COOKIE_ATTRS.getTag()));
        assertThat(alert.getUri(), is(equalTo("http://example.com")));
        assertThat(alert.getOtherInfo(), containsString("https://example.com"));
        assertThat(alert.getRisk(), is(equalTo(Alert.RISK_MEDIUM)));
        assertThat(alert.getConfidence(), is(equalTo(Alert.CONFIDENCE_MEDIUM)));
    }

    private static HttpMessage getHttpMessage(int port) throws Exception {
        HttpMessage msg = new HttpMessage();
        StringBuilder header = new StringBuilder();
        header.append("GET http://localhost");
        if (port != -1) {
            header.append(':').append(port);
        }
        header.append(" HTTP/1.1\r\n");
        msg.setRequestHeader(header.toString());
        return msg;
    }

    private static class TestHttpSenderImpl implements AutoCloseable {

        @SuppressWarnings("unchecked")
        private final HttpSenderImpl<HttpSenderContext> httpSender = mock(HttpSenderImpl.class);

        TestHttpSenderImpl() {
            HttpSender.setImpl(httpSender);
        }

        void throwException(IOException exception) throws IOException {
            doThrow(exception)
                    .when(httpSender)
                    .sendAndReceive(any(HttpSenderContext.class), any(), any(), any());
        }

        @Override
        public void close() {
            HttpSender.setImpl(null);
        }
    }
}
