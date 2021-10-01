/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2019 The ZAP Development Team
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
package org.zaproxy.zap.extension.pscanrulesBeta;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

import java.io.IOException;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;

class HeartBleedScannerUnitTest extends PassiveScannerTest<HeartBleedScanRule> {

    private static final String URI = "https://www.example.com/test/";
    private static final String SAFE_OPENSSL_VERSION = "OpenSSL/1.1.1";

    @Override
    protected HeartBleedScanRule createScanner() {
        return new HeartBleedScanRule();
    }

    @Test
    void givenNoServerHeaderThenNoAlertRaised() throws IOException {
        // Given
        HttpMessage msg = createMsg();

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), is(0));
    }

    @Test
    void givenServerHeaderWithSafeOpenSSLThenNoAlertRaised() throws IOException {
        // Given
        HttpMessage msg = createMsg("Apache/2.4.1 (" + SAFE_OPENSSL_VERSION + ")");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), is(0));
    }

    @Test
    void givenServerHeaderWithoutOpenSSLThenNoAlertRaised() throws IOException {
        // Given
        HttpMessage msg = createMsg("Apache/2.4.1");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), is(0));
    }

    @Test
    void givenServerHeaderWithVulnerableLowercaseOpenSSLThenAlertRaised() throws IOException {
        // Given
        String opensslVersion = "openssl/1.0.1-beta1";
        HttpMessage msg = createMsg(String.format("Apache-Coyote/1.1 (%s)", opensslVersion));

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), is(1));
        assertAlertAttributes(alertsRaised.get(0), opensslVersion);
    }

    @Test
    void givenServerHeaderWithVulnerableOpenSSLThenAlertRaised() throws IOException {
        for (String version : HeartBleedScanRule.openSSLvulnerableVersions) {
            // Given
            alertsRaised.clear();
            HttpMessage msg = createMsg(String.format("Apache-Coyote/1.1 (OpenSSL/%s)", version));

            // When
            scanHttpResponseReceive(msg);

            // Then
            String reason = "Expecting alert to be raised for OpenSSL/" + version;
            assertThat(reason, alertsRaised.size(), is(1));
            assertAlertAttributes(alertsRaised.get(0), "OpenSSL/" + version);
        }
    }

    @Test
    void givenServerHeaderWithVulnerableAndSafeOpenSSLVersionsThenAlertRaised() throws IOException {
        // Given
        String vulnerableVersion = "openssl/1.0.1";
        HttpMessage msg = createMsg(String.format("Apache-Coyote/1.1 (%s)", vulnerableVersion));
        addServerHeader(msg, String.format("Apache-Coyote/1.1 (%s)", SAFE_OPENSSL_VERSION));

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), is(1));
        assertAlertAttributes(alertsRaised.get(0), vulnerableVersion);
    }

    @Test
    void givenServerHeaderWithSafeAndVulnerableOpenSSLVersionsThenAlertRaised() throws IOException {
        // Given
        String vulnerableVersion = "openssl/1.0.1";
        HttpMessage msg = createMsg(String.format("Apache-Coyote/1.1 (%s)", SAFE_OPENSSL_VERSION));
        addServerHeader(msg, String.format("Apache-Coyote/1.1 (%s)", vulnerableVersion));

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), is(1));
        assertAlertAttributes(alertsRaised.get(0), vulnerableVersion);
    }

    void shouldReturnExpectedMappings() {
        // Given / When
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(tags.size(), is(equalTo(2)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A06_VULN_COMP.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A09_VULN_COMP.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A06_VULN_COMP.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A06_VULN_COMP.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A09_VULN_COMP.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A09_VULN_COMP.getValue())));
    }

    private static HttpMessage createMsg(String serverHeader) throws HttpMalformedHeaderException {
        HttpMessage msg = createMsg();
        addServerHeader(msg, serverHeader);
        return msg;
    }

    private static HttpMessage createMsg() throws HttpMalformedHeaderException {
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET " + URI + " HTTP/1.1");
        return msg;
    }

    private static void addServerHeader(HttpMessage msg, String serverHeader) {
        msg.getResponseHeader().addHeader("Server", serverHeader);
    }

    private static void assertAlertAttributes(Alert alert, String opensslVersion) {
        assertThat(alert.getRisk(), is(Alert.RISK_HIGH));
        assertThat(alert.getConfidence(), is(Alert.CONFIDENCE_LOW));
        assertThat(alert.getName(), is(getLocalisedString("name")));
        assertThat(alert.getDescription(), is(getLocalisedString("desc")));
        assertThat(alert.getUri(), is(URI));
        assertThat(alert.getOtherInfo(), is(getLocalisedString("extrainfo", opensslVersion)));
        assertThat(alert.getSolution(), is(getLocalisedString("soln")));
        assertThat(alert.getReference(), is(getLocalisedString("refs")));
        assertThat(alert.getEvidence(), is(opensslVersion));
        assertThat(alert.getCweId(), is(119));
        assertThat(alert.getWascId(), is(20));
    }

    private static String getLocalisedString(String key, Object... params) {
        return Constant.messages.getString("pscanbeta.heartbleed." + key, params);
    }
}
