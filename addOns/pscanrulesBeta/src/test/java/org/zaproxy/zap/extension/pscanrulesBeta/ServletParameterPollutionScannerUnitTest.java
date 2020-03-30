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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Before;
import org.junit.Test;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;

public class ServletParameterPollutionScannerUnitTest
        extends PassiveScannerTest<ServletParameterPollutionScanner> {

    public static final String URI = "http://www.example.com/test/";

    @Override
    protected ServletParameterPollutionScanner createScanner() {
        return new ServletParameterPollutionScanner();
    }

    @Before
    public void before() {
        rule.setAlertThreshold(AlertThreshold.LOW);
    }

    @Test
    public void givenNoFormsWhenScanHttpResponseReceiveThenNoAlertsRaised() throws Exception {
        // Given - Threshold set LOW in before()
        HttpMessage msg = createHttpMessageFromHtml("");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertNumberOfAlertsRaised(0);
    }

    @Test
    public void givenFormWithActionAttributeWhenScanHttpResponseReceiveThenNoAlertsRaised()
            throws Exception {
        // Given - Threshold set LOW in before()
        HttpMessage msg = createHttpMessageFromHtml("<form action='ActionMan'>");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertNumberOfAlertsRaised(0);
    }

    @Test
    public void
            givenFormWithNoActionAttributeWhenScanHttpResponseReceiveThenAlertRaisedAndAlertPopulated()
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
    public void
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
    public void
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
    public void givenFormWithValuelessActionAttributeWhenScanHttpResponseReceiveThenAlertRaised()
            throws Exception {
        // Given - Threshold set LOW in before()
        HttpMessage msg = createHttpMessageFromHtml("<form action />");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertNumberOfAlertsRaised(1);
    }

    @Test
    public void givenFormWithEmptyActionAttributeWhenScanHttpResponseReceiveThenAlertRaised()
            throws Exception {
        // Given - Threshold set LOW in before()
        HttpMessage msg = createHttpMessageFromHtml("<form action='' />");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertNumberOfAlertsRaised(1);
    }

    @Test
    public void
            givenFormWithEmptyAndPopulatedActionAttributesWhenScanHttpResponseReceiveThenAlertRaised()
                    throws Exception {
        // Given - Threshold set LOW in before()
        HttpMessage msg = createHttpMessageFromHtml("<form action action='ActionMan' />");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertNumberOfAlertsRaised(1);
    }

    @Test
    public void
            givenTwoFormsWithNoActionAttributeWhenScanHttpResponseReceiveThenOnlyOneAlertRaised()
                    throws Exception {
        // Given - Threshold set LOW in before()
        HttpMessage msg = createHttpMessageFromHtml("<form /><form />");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertNumberOfAlertsRaised(1);
    }

    private Alert getFirstAlertRaised() {
        assertTrue("Expected Alert but none raised.", alertsRaised.size() > 0);
        return alertsRaised.get(0);
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
