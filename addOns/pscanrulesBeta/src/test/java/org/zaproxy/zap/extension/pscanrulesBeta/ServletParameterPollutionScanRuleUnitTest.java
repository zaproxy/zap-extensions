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
package org.zaproxy.zap.extension.pscanrulesBeta;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;

class ServletParameterPollutionScanRuleUnitTest
        extends PassiveScannerTest<ServletParameterPollutionScanRule> {

    public static final String URI = "http://www.example.com/test/";

    @Override
    protected ServletParameterPollutionScanRule createScanner() {
        return new ServletParameterPollutionScanRule();
    }

    @BeforeEach
    void before() {
        rule.setAlertThreshold(AlertThreshold.LOW);
        when(passiveScanData.getTechSet()).thenReturn(TechSet.getAllTech());
    }

    @Test
    void givenNoFormsWhenScanHttpResponseReceiveThenNoAlertsRaised() throws Exception {
        // Given - Threshold set LOW in before()
        HttpMessage msg = createHttpMessageFromHtml("");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertNumberOfAlertsRaised(0);
    }

    @Test
    void givenFormWithActionAttributeWhenScanHttpResponseReceiveThenNoAlertsRaised()
            throws Exception {
        // Given - Threshold set LOW in before()
        HttpMessage msg = createHttpMessageFromHtml("<form action='ActionMan'>");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertNumberOfAlertsRaised(0);
    }

    @Test
    void givenFormWithNoActionAttributeWhenScanHttpResponseReceiveThenAlertRaisedAndAlertPopulated()
            throws Exception {
        // Given - Threshold set LOW in before()
        HttpMessage msg = createHttpMessageFromHtml("<form />");
        // When
        scanHttpResponseReceive(msg);
        Alert alert = getFirstAlertRaised();
        // Then
        assertEquals(alert.getRisk(), Alert.RISK_MEDIUM);
        assertEquals(alert.getConfidence(), Alert.CONFIDENCE_LOW);
        assertEquals(alert.getUri(), URI);
        assertEquals(alert.getEvidence(), "<form />");
    }

    @Test
    void
            givenFormWithNoActionAttributeWhenScanHttpResponseReceiveThenAtMediumThresholdThenNoAlertRaised()
                    throws Exception {
        // Given
        HttpMessage msg = createHttpMessageFromHtml("<form />");
        rule.setAlertThreshold(AlertThreshold.MEDIUM);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertNumberOfAlertsRaised(0);
    }

    @Test
    void
            givenFormWithNoActionAttributeWhenScanHttpResponseReceiveThenAtHighThresholdThenNoAlertRaised()
                    throws Exception {
        // Given
        HttpMessage msg = createHttpMessageFromHtml("<form />");
        rule.setAlertThreshold(AlertThreshold.HIGH);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertNumberOfAlertsRaised(0);
    }

    @Test
    void
            givenFormWithNoActionAttributeWhenScanHttpResponseReceiveWithTechNotRelevantThenNoAlertRaised()
                    throws Exception {
        // Given
        HttpMessage msg = createHttpMessageFromHtml("<form />");
        when(passiveScanData.getTechSet()).thenReturn(new TechSet(new Tech[] {Tech.Access}));
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertNumberOfAlertsRaised(0);
    }

    @Test
    void givenFormWithNoActionAttributeWhenScanHttpResponseReceiveWithTechRelevantThenAlertRaised()
            throws Exception {
        // Given
        HttpMessage msg = createHttpMessageFromHtml("<form />");
        when(passiveScanData.getTechSet()).thenReturn(new TechSet(new Tech[] {Tech.JSP_SERVLET}));
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertNumberOfAlertsRaised(1);
    }

    @Test
    void givenFormWithValuelessActionAttributeWhenScanHttpResponseReceiveThenAlertRaised()
            throws Exception {
        // Given - Threshold set LOW in before()
        HttpMessage msg = createHttpMessageFromHtml("<form action />");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertNumberOfAlertsRaised(1);
    }

    @Test
    void givenFormWithEmptyActionAttributeWhenScanHttpResponseReceiveThenAlertRaised()
            throws Exception {
        // Given - Threshold set LOW in before()
        HttpMessage msg = createHttpMessageFromHtml("<form action='' />");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertNumberOfAlertsRaised(1);
    }

    @Test
    void givenFormWithEmptyAndPopulatedActionAttributesWhenScanHttpResponseReceiveThenAlertRaised()
            throws Exception {
        // Given - Threshold set LOW in before()
        HttpMessage msg = createHttpMessageFromHtml("<form action action='ActionMan' />");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertNumberOfAlertsRaised(1);
    }

    @Test
    void givenTwoFormsWithNoActionAttributeWhenScanHttpResponseReceiveThenOnlyOneAlertRaised()
            throws Exception {
        // Given - Threshold set LOW in before()
        HttpMessage msg = createHttpMessageFromHtml("<form /><form />");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertNumberOfAlertsRaised(1);
    }

    private Alert getFirstAlertRaised() {
        assertTrue(alertsRaised.size() > 0, "Expected Alert but none raised.");
        return alertsRaised.get(0);
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(tags.size(), is(equalTo(2)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A04_INSECURE_DESIGN.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A04_INSECURE_DESIGN.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A04_INSECURE_DESIGN.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getValue())));
    }

    private void assertNumberOfAlertsRaised(int expected) {
        assertEquals(expected, alertsRaised.size());
    }

    private HttpMessage createHttpMessageFromHtml(String html) throws HttpMalformedHeaderException {
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET " + URI + " HTTP/1.1");
        msg.setResponseHeader("HTTP/1.1 200\r\n");
        msg.setResponseBody(html);
        return msg;
    }
}
