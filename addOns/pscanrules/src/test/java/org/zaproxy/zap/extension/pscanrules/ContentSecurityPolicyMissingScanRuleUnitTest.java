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
package org.zaproxy.zap.extension.pscanrules;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

import java.util.List;
import java.util.Map;
import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;

class ContentSecurityPolicyMissingScanRuleUnitTest
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
    void givenMissingCspHeaderThenAlertRaised() throws Exception {
        // Given
        HttpMessage msg = createHttpMessageWithHeaders(HEADER_HTML);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertContentSecurityPolicyAlertRaised();
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "Content-Security-Policy",
                "CONTENT-SECURITY-POLICY",
                "content-security-policy"
            })
    void givenMissingCspHeaderWithMetaThenAlertNotRaised(String name) throws Exception {
        // Given
        HttpMessage msg = createHttpMessageWithHeaders(HEADER_HTML);
        msg.setResponseBody(
                "<html><head><meta http-equiv=\""
                        + name
                        + "\" content=\"default-src 'self'\"></head><H1>Test</H1></html>");
        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), is(0));
    }

    @Test
    void givenMissingCspHeaderInRedirectAtMediumAlertThresholdThenNoAlertRaised() throws Exception {
        // Given
        rule.setAlertThreshold(Plugin.AlertThreshold.MEDIUM);
        HttpMessage msg = createHttpMessageWithHeaders(301, HEADER_HTML);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), is(0));
    }

    @Test
    void givenMissingCspHeaderInRedirectAtLowAlertThresholdThenAlertRaised() throws Exception {
        // Given
        rule.setAlertThreshold(Plugin.AlertThreshold.LOW);
        HttpMessage msg = createHttpMessageWithHeaders(301, HEADER_HTML);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertContentSecurityPolicyAlertRaised();
    }

    @Test
    void givenCspHeaderThenNoAlertRaised() throws Exception {
        // Given
        HttpMessage msg = createHttpMessageWithHeaders(HEADER_HTML, HEADER_CSP);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), is(0));
    }

    @Test
    void givenWebKitThenTwoAlertsRaised() throws Exception {
        // Given
        HttpMessage msg = createHttpMessageWithHeaders(HEADER_HTML, HEADER_WEBKIT_CSP);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), is(2));
        assertCSPAlertAttributes(alertsRaised.get(0), "", Alert.RISK_MEDIUM, "10038-1");
        assertCSPAlertAttributes(alertsRaised.get(1), "obs.", Alert.RISK_INFO, "10038-2");
    }

    @Test
    void givenXCspThenTwoAlertsRaised() throws Exception {
        // Given
        HttpMessage msg = createHttpMessageWithHeaders(HEADER_HTML, HEADER_X_CSP);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), is(2));
        assertCSPAlertAttributes(alertsRaised.get(0), "", Alert.RISK_MEDIUM, "10038-1");
        assertCSPAlertAttributes(alertsRaised.get(1), "obs.", Alert.RISK_INFO, "10038-2");
    }

    @Test
    void givenAllCspHeadersThenAlertRaised() throws Exception {
        // Given
        String[] headers = {HEADER_HTML, HEADER_CSP, HEADER_X_CSP, HEADER_WEBKIT_CSP};
        HttpMessage msg = createHttpMessageWithHeaders(headers);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertObsoleteSecurityPolicyAlertRaised();
    }

    @Test
    void givenTextContentTypeAtMediumAlertThresholdThenNoAlertRaised() throws Exception {
        // Given
        rule.setAlertThreshold(Plugin.AlertThreshold.MEDIUM);
        HttpMessage msg = createHttpMessageWithHeaders(HEADER_TEXT);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), is(0));
    }

    @Test
    void givenTextContentTypeAtLowAlertThresholdThenAlertRaised() throws Exception {
        // Given
        rule.setAlertThreshold(Plugin.AlertThreshold.LOW);
        HttpMessage msg = createHttpMessageWithHeaders(HEADER_TEXT);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertContentSecurityPolicyAlertRaised();
    }

    @Test
    void givenTextContentTypeWithCspHeaderAtLowAlertThresholdThenNoAlertRaised() throws Exception {
        // Given
        rule.setAlertThreshold(Plugin.AlertThreshold.LOW);
        String[] headers = {HEADER_TEXT, HEADER_CSP};
        HttpMessage msg = createHttpMessageWithHeaders(headers);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), is(0));
    }

    @Test
    void givenTextContentTypeWithAllCspHeadersAtLowAlertThresholdThenAlertRaised()
            throws Exception {
        // Given
        rule.setAlertThreshold(Plugin.AlertThreshold.LOW);
        String[] headers = {HEADER_TEXT, HEADER_CSP, HEADER_X_CSP, HEADER_WEBKIT_CSP};
        HttpMessage msg = createHttpMessageWithHeaders(headers);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertObsoleteSecurityPolicyAlertRaised();
    }

    @Test
    void givenTextContentTypeWithXCspAtLowAlertThresholdThenAlertRaised() throws Exception {
        // Given
        rule.setAlertThreshold(Plugin.AlertThreshold.LOW);
        String[] headers = {HEADER_TEXT, HEADER_CSP, HEADER_X_CSP};
        HttpMessage msg = createHttpMessageWithHeaders(headers);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertObsoleteSecurityPolicyAlertRaised();
    }

    @Test
    void givenTextContentTypeWithWebkitAtLowAlertThresholdThenAlertRaised() throws Exception {
        // Given
        rule.setAlertThreshold(Plugin.AlertThreshold.LOW);
        String[] headers = {HEADER_TEXT, HEADER_CSP, HEADER_WEBKIT_CSP};
        HttpMessage msg = createHttpMessageWithHeaders(headers);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertObsoleteSecurityPolicyAlertRaised();
    }

    @Test
    void givenReportOnlyCspThenInfoAlertRaised() throws Exception {
        // Given
        rule.setAlertThreshold(Plugin.AlertThreshold.MEDIUM);
        HttpMessage msg = createHttpMessageWithHeaders(HEADER_HTML, HEADER_REPORT_ONLY);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), is(2));
        assertCSPAlertAttributes(alertsRaised.get(0), "", Alert.RISK_MEDIUM, "10038-1");
        assertCSPAlertAttributes(alertsRaised.get(1), "ro.", Alert.RISK_INFO, "10038-3");
        assertThat(alertsRaised.get(1).getReference(), is(getLocalisedString("ro.refs")));
    }

    @Test
    void givenReportOnlyAndCspHeadersThenInfoAlertRaised() throws Exception {
        // Given
        rule.setAlertThreshold(Plugin.AlertThreshold.MEDIUM);
        HttpMessage msg = createHttpMessageWithHeaders(HEADER_HTML, HEADER_REPORT_ONLY, HEADER_CSP);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), is(1));
        assertCSPAlertAttributes(alertsRaised.get(0), "ro.", Alert.RISK_INFO, "10038-3");
        assertThat(alertsRaised.get(0).getReference(), is(getLocalisedString("ro.refs")));
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(tags.size(), is(equalTo(2)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getValue())));
    }

    @Test
    void shouldReturnExampleAlerts() {
        // Given / When
        List<Alert> alerts = rule.getExampleAlerts();

        // Then
        assertThat(alerts.size(), is(equalTo(3)));
        assertCSPAlertAttributes(alerts.get(0), "", Alert.RISK_MEDIUM, "10038-1");
        assertCSPAlertAttributes(alerts.get(1), "obs.", Alert.RISK_INFO, "10038-2");
        assertCSPAlertAttributes(alerts.get(2), "ro.", Alert.RISK_INFO, "10038-3");
    }

    @Test
    @Override
    public void shouldHaveValidReferences() {
        super.shouldHaveValidReferences();
    }

    private void assertContentSecurityPolicyAlertRaised() {
        assertThat(alertsRaised.size(), is(1));
        assertCSPAlertAttributes(alertsRaised.get(0), "", Alert.RISK_MEDIUM, "10038-1");
        assertThat(alertsRaised.get(0).getReference(), is(getLocalisedString("refs")));
    }

    private void assertObsoleteSecurityPolicyAlertRaised() {
        assertThat(alertsRaised.size(), is(1));
        assertCSPAlertAttributes(alertsRaised.get(0), "obs.", Alert.RISK_INFO, "10038-2");
        assertThat(alertsRaised.get(0).getReference(), is(getLocalisedString("refs")));
    }

    private static void assertCSPAlertAttributes(
            Alert alert, String key, int expectedRisk, String alertRef) {
        assertThat(alert.getRisk(), is(expectedRisk));
        assertThat(alert.getName(), is(getLocalisedString(key + "name")));
        assertThat(alert.getDescription(), is(getLocalisedString(key + "desc")));
        assertThat(alert.getSolution(), is(getLocalisedString("soln")));
        assertThat(alert.getConfidence(), is(Alert.CONFIDENCE_HIGH));
        assertThat(alert.getCweId(), is(693));
        assertThat(alert.getWascId(), is(15));
        assertThat(alert.getUri(), is(URI));
        assertThat(alert.getAlertRef(), is(alertRef));
    }

    private static String getLocalisedString(String key) {
        return Constant.messages.getString("pscanrules.contentsecuritypolicymissing." + key);
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
