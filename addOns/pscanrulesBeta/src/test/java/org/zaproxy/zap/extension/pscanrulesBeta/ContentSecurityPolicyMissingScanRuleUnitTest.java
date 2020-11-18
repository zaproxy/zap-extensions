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
import static org.hamcrest.Matchers.is;

import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin;
import org.parosproxy.paros.network.HttpMessage;

public class ContentSecurityPolicyMissingScanRuleUnitTest
        extends PassiveScannerTest<ContentSecurityPolicyMissingScanRule> {
    private static final String URI = "https://www.example.com";
    private static final String HEADER_HTML = "Content-Type: text/html";
    private static final String HEADER_TEXT = "Content-Type: text/plain";
    private static final String HEADER_CSP = "Content-Security-Policy: x";
    private static final String HEADER_X_CSP = "X-Content-Security-Policy: x";
    private static final String HEADER_WEBKIT_CSP = "X-WebKit-CSP: x";
    private static final String HEADER_REPORT_ONLY = "Content-Security-Policy-Report-Only: x";

    @Override
    protected ContentSecurityPolicyMissingScanRule createScanner() {
        return new ContentSecurityPolicyMissingScanRule();
    }

    @Test
    public void givenMissingCspHeaderThenAlertRaised() throws Exception {
        // Given
        HttpMessage msg = createHttpMessageWithHeaders(HEADER_HTML);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertContentSecurityPolicyAlertRaised();
    }

    @Test
    public void givenMissingCspHeaderInRedirectAtMediumAlertThresholdThenNoAlertRaised()
            throws Exception {
        // Given
        rule.setAlertThreshold(Plugin.AlertThreshold.MEDIUM);
        HttpMessage msg = createHttpMessageWithHeaders(301, HEADER_HTML);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), is(0));
    }

    @Test
    public void givenMissingCspHeaderInRedirectAtLowAlertThresholdThenAlertRaised()
            throws Exception {
        // Given
        rule.setAlertThreshold(Plugin.AlertThreshold.LOW);
        HttpMessage msg = createHttpMessageWithHeaders(301, HEADER_HTML);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertContentSecurityPolicyAlertRaised();
    }

    @Test
    public void givenCspHeaderAtMediumAlertThresholdThenNoAlertRaised() throws Exception {
        // Given
        rule.setAlertThreshold(Plugin.AlertThreshold.MEDIUM);
        HttpMessage msg = createHttpMessageWithHeaders(HEADER_HTML, HEADER_CSP);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), is(0));
    }

    @Test
    public void givenCspHeaderAtLowAlertThresholdThenAlertRaised() throws Exception {
        // Given
        rule.setAlertThreshold(Plugin.AlertThreshold.LOW);
        HttpMessage msg = createHttpMessageWithHeaders(HEADER_HTML, HEADER_CSP);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertContentSecurityPolicyAlertRaised();
    }

    @Test
    public void givenAllCspHeadersButXCspAtLowAlertThresholdThenAlertRaised() throws Exception {
        // Given
        rule.setAlertThreshold(Plugin.AlertThreshold.LOW);
        HttpMessage msg = createHttpMessageWithHeaders(HEADER_HTML, HEADER_CSP, HEADER_WEBKIT_CSP);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertContentSecurityPolicyAlertRaised();
    }

    @Test
    public void givenAllCspHeadersButWebkitCspAtLowAlertThresholdThenAlertRaised()
            throws Exception {
        // Given
        rule.setAlertThreshold(Plugin.AlertThreshold.LOW);
        HttpMessage msg = createHttpMessageWithHeaders(HEADER_HTML, HEADER_CSP, HEADER_X_CSP);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertContentSecurityPolicyAlertRaised();
    }

    @Test
    public void givenAllCspHeadersAtLowAlertThresholdThenNoAlertRaised() throws Exception {
        // Given
        rule.setAlertThreshold(Plugin.AlertThreshold.LOW);
        String[] headers = {HEADER_HTML, HEADER_CSP, HEADER_X_CSP, HEADER_WEBKIT_CSP};
        HttpMessage msg = createHttpMessageWithHeaders(headers);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), is(0));
    }

    @Test
    public void givenTextContentTypeAtMediumAlertThresholdThenNoAlertRaised() throws Exception {
        // Given
        rule.setAlertThreshold(Plugin.AlertThreshold.MEDIUM);
        HttpMessage msg = createHttpMessageWithHeaders(HEADER_TEXT);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), is(0));
    }

    @Test
    public void givenTextContentTypeAtLowAlertThresholdThenAlertRaised() throws Exception {
        // Given
        rule.setAlertThreshold(Plugin.AlertThreshold.LOW);
        HttpMessage msg = createHttpMessageWithHeaders(HEADER_TEXT);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertContentSecurityPolicyAlertRaised();
    }

    @Test
    public void givenTextContentTypeWithCspHeadersAtLowAlertThresholdThenNoAlertRaised()
            throws Exception {
        // Given
        rule.setAlertThreshold(Plugin.AlertThreshold.LOW);
        String[] headers = {HEADER_TEXT, HEADER_CSP, HEADER_X_CSP, HEADER_WEBKIT_CSP};
        HttpMessage msg = createHttpMessageWithHeaders(headers);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), is(0));
    }

    @Test
    public void givenReportOnlyCspThenInfoAlertRaised() throws Exception {
        // Given
        rule.setAlertThreshold(Plugin.AlertThreshold.MEDIUM);
        HttpMessage msg = createHttpMessageWithHeaders(HEADER_HTML, HEADER_REPORT_ONLY);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), is(2));
        assertCSPAlertAttributes(alertsRaised.get(0), "", Alert.RISK_MEDIUM);
        assertCSPAlertAttributes(alertsRaised.get(1), "ro.", Alert.RISK_INFO);
    }

    @Test
    public void givenReportOnlyAndCspHeadersThenInfoAlertRaised() throws Exception {
        // Given
        rule.setAlertThreshold(Plugin.AlertThreshold.MEDIUM);
        HttpMessage msg = createHttpMessageWithHeaders(HEADER_HTML, HEADER_REPORT_ONLY, HEADER_CSP);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), is(1));
        assertCSPAlertAttributes(alertsRaised.get(0), "ro.", Alert.RISK_INFO);
    }

    private void assertContentSecurityPolicyAlertRaised() {
        assertThat(alertsRaised.size(), is(1));
        assertCSPAlertAttributes(alertsRaised.get(0), "", Alert.RISK_MEDIUM);
    }

    private static void assertCSPAlertAttributes(Alert alert, String key, int expectedRisk) {
        assertThat(alert.getRisk(), is(expectedRisk));
        assertThat(alert.getName(), is(getLocalisedString(key + "name")));
        assertThat(alert.getDescription(), is(getLocalisedString(key + "desc")));
        assertThat(alert.getReference(), is(getLocalisedString(key + "refs")));
        assertThat(alert.getSolution(), is(getLocalisedString("soln")));
        assertThat(alert.getConfidence(), is(Alert.CONFIDENCE_HIGH));
        assertThat(alert.getCweId(), is(16));
        assertThat(alert.getWascId(), is(15));
        assertThat(alert.getUri(), is(URI));
    }

    private static String getLocalisedString(String key) {
        return Constant.messages.getString("pscanbeta.contentsecuritypolicymissing." + key);
    }

    private static HttpMessage createHttpMessageWithHeaders(String... headers) throws Exception {
        return createHttpMessageWithHeaders(200, headers);
    }

    private static HttpMessage createHttpMessageWithHeaders(int responseCode, String... headers)
            throws Exception {
        HttpMessage msg = new HttpMessage(new URI(URI, false));
        msg.setResponseHeader(
                "HTTP/1.1 " + responseCode + " OK\r\n" + String.join("\r\n", headers));
        return msg;
    }
}
