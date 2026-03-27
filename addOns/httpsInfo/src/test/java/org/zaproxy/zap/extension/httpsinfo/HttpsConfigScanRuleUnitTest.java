/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.zap.extension.httpsinfo;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.startsWith;

import java.net.HttpURLConnection;
import java.util.Map;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.zap.testutils.ActiveScannerTestUtils;

/**
 * Unit tests for {@link HttpsConfigScanRule}.
 *
 * <p>Uses SSL.com test certificates from <a
 * href="https://www.ssl.com/sample-valid-revoked-and-expired-ssl-tls-certificates/">SSL.com sample
 * certificates</a> for integration tests. If those certificates expire or change, the integration
 * tests may need to be updated.
 */
class HttpsConfigScanRuleUnitTest extends ActiveScannerTestUtils<HttpsConfigScanRule> {

    private static final String SSLCOM_VALID_DV_RSA = "https://test-dv-rsa.ssl.com/";
    private static final String SSLCOM_EXPIRED_RSA_DV = "https://expired-rsa-dv.ssl.com/";
    private static final String SSLCOM_REVOKED_RSA_EV = "https://revoked-rsa-ev.ssl.com/";

    @Override
    protected HttpsConfigScanRule createScanner() {
        return new HttpsConfigScanRule();
    }

    @Override
    protected void setUpMessages() {
        mockMessages(new ExtensionHttpsInfo());
    }

    @Test
    void shouldSkipHttpSites() throws HttpMalformedHeaderException {
        // Given - HTTP message (from local test server)
        HttpMessage httpMessage = getHttpMessage("/");

        // When
        rule.init(httpMessage, parent);
        rule.scan();

        // Then - no alerts raised (HTTP is skipped)
        assertThat(alertsRaised, is(empty()));
    }

    @Test
    void shouldHaveExampleAlerts() {
        // Given / When
        var alerts = rule.getExampleAlerts();

        // Then
        assertThat(alerts, is(not(empty())));
        assertThat(alerts, hasSize(2));

        Alert infoAlert = alerts.get(0);
        assertThat(infoAlert.getAlertRef(), is(equalTo("10205-1")));
        assertThat(infoAlert.getRisk(), is(equalTo(Alert.RISK_INFO)));
        assertThat(infoAlert.getOtherInfo(), is(notNullValue()));
        assertThat(infoAlert.getOtherInfo(), startsWith("Server: example.com"));

        Alert failureAlert = alerts.get(1);
        assertThat(failureAlert.getAlertRef(), is(equalTo("10205-2")));
        assertThat(failureAlert.getRisk(), is(equalTo(Alert.RISK_HIGH)));
        assertThat(failureAlert.getName(), is(notNullValue()));
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
        assertThat(tags.size(), is(equalTo(10)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2025_A04_CRYPTO_FAIL.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A02_CRYPO_FAIL.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A03_DATA_EXPOSED.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.WSTG_V42_CRYP_01_TLS.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(CommonAlertTag.SYSTEMIC.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.QA_STD.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.QA_FULL.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.API.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.PENTEST.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.SEQUENCE.getTag()), is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2025_A04_CRYPTO_FAIL.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2025_A04_CRYPTO_FAIL.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A02_CRYPO_FAIL.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A02_CRYPO_FAIL.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A03_DATA_EXPOSED.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A03_DATA_EXPOSED.getValue())));
        assertThat(
                tags.get(CommonAlertTag.WSTG_V42_CRYP_01_TLS.getTag()),
                is(equalTo(CommonAlertTag.WSTG_V42_CRYP_01_TLS.getValue())));
        assertThat(
                tags.get(CommonAlertTag.SYSTEMIC.getTag()),
                is(equalTo(CommonAlertTag.SYSTEMIC.getValue())));
    }

    @Test
    @EnabledIf("isValidHttpsServerAvailable")
    void shouldRaiseInfoAlertForValidHttpsSite() throws Exception {
        // Given - HTTPS message to SSL.com valid test cert
        HttpMessage httpsMessage = createHttpsMessage(SSLCOM_VALID_DV_RSA);

        // When
        rule.init(httpsMessage, parent);
        rule.scan();

        // Then - info alert with cert details (may also have failure alert depending on DeepViolet)
        assertThat(alertsRaised, hasSize(2));
        Alert infoAlert =
                alertsRaised.stream()
                        .filter(a -> "10205-1".equals(a.getAlertRef()))
                        .findFirst()
                        .orElse(null);
        assertThat(infoAlert, is(notNullValue()));
        assertThat(infoAlert.getRisk(), is(equalTo(Alert.RISK_INFO)));
        assertThat(infoAlert.getOtherInfo(), is(notNullValue()));
        assertThat(infoAlert.getOtherInfo(), startsWith("Server: test-dv-rsa.ssl.com"));
    }

    @Test
    @EnabledIf("isExpiredServerAvailable")
    void shouldRaiseFailureAlertForExpiredCertificate() throws Exception {
        // Given - HTTPS message to SSL.com expired test cert
        HttpMessage httpsMessage = createHttpsMessage(SSLCOM_EXPIRED_RSA_DV);

        // When
        rule.init(httpsMessage, parent);
        rule.scan();

        // Then - 2 alerts: info and failure (10205-2) for expired cert
        assertThat(alertsRaised, hasSize(2));
        Alert failureAlert =
                alertsRaised.stream()
                        .filter(a -> "10205-2".equals(a.getAlertRef()))
                        .findFirst()
                        .orElse(null);
        assertThat(failureAlert, is(notNullValue()));
        assertThat(failureAlert.getRisk(), is(equalTo(Alert.RISK_HIGH)));
        assertThat(failureAlert.getOtherInfo(), is(notNullValue()));
        assertThat(failureAlert.getOtherInfo(), containsString("expired"));
    }

    @Test
    @EnabledIf("isRevokedServerAvailable")
    void shouldRaiseFailureAlertForRevokedCertificate() throws Exception {
        // Given - HTTPS message to SSL.com revoked test cert
        HttpMessage httpsMessage = createHttpsMessage(SSLCOM_REVOKED_RSA_EV);

        // When
        rule.init(httpsMessage, parent);
        rule.scan();

        // Then - 2 alerts: info and failure (10205-2) for revoked cert
        assertThat(alertsRaised, hasSize(2));
        Alert failureAlert =
                alertsRaised.stream()
                        .filter(a -> "10205-2".equals(a.getAlertRef()))
                        .findFirst()
                        .orElse(null);
        assertThat(failureAlert, is(notNullValue()));
        assertThat(failureAlert.getRisk(), is(equalTo(Alert.RISK_HIGH)));
        assertThat(failureAlert.getOtherInfo(), is(notNullValue()));
        assertThat(failureAlert.getOtherInfo(), containsString("revoked"));
    }

    private static HttpMessage createHttpsMessage(String url) throws Exception {
        HttpMessage msg = new HttpMessage(new URI(url, true));

        HttpResponseHeader respHeader = new HttpResponseHeader();
        respHeader.setStatusCode(200);
        respHeader.setHeader("Content-Type", "text/html");
        msg.setResponseHeader(respHeader);
        msg.setResponseBody("");

        return msg;
    }

    @SuppressWarnings("unused")
    private static boolean isValidHttpsServerAvailable() {
        return isServerAvailable(SSLCOM_VALID_DV_RSA, false);
    }

    @SuppressWarnings("unused")
    private static boolean isExpiredServerAvailable() {
        return isServerAvailable(SSLCOM_EXPIRED_RSA_DV, true);
    }

    @SuppressWarnings("unused")
    private static boolean isRevokedServerAvailable() {
        return isServerAvailable(SSLCOM_REVOKED_RSA_EV, true);
    }

    /**
     * Checks if the given HTTPS server is reachable. For servers with invalid certs (expired,
     * revoked), {@code trustAllCerts} must be true to establish a connection.
     */
    private static boolean isServerAvailable(String url, boolean trustAllCerts) {
        try {
            HttpURLConnection conn =
                    (HttpURLConnection) java.net.URI.create(url).toURL().openConnection();
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);
            conn.setRequestMethod("HEAD");
            if (trustAllCerts && conn instanceof HttpsURLConnection httpsConn) {
                SSLContext sslContext = SSLContext.getInstance("TLS");
                sslContext.init(
                        null,
                        new TrustManager[] {
                            new X509TrustManager() {
                                @Override
                                public void checkClientTrusted(
                                        java.security.cert.X509Certificate[] chain,
                                        String authType) {}

                                @Override
                                public void checkServerTrusted(
                                        java.security.cert.X509Certificate[] chain,
                                        String authType) {}

                                @Override
                                public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                                    return new java.security.cert.X509Certificate[0];
                                }
                            }
                        },
                        new java.security.SecureRandom());
                httpsConn.setSSLSocketFactory(sslContext.getSocketFactory());
            }
            int code = conn.getResponseCode();
            return code >= 200 && code < 400;
        } catch (Exception e) {
            return false;
        }
    }
}
