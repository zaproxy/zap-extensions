/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP development team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.zaproxy.zap.extension.pscanrulesBeta;

import org.junit.Test;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class ServletParameterPollutionScannerUnitTest extends PassiveScannerTest {

    public static final String URI = "http://www.example.com/test/";

    @Override
    protected ServletParameterPollutionScanner createScanner() {
        return new ServletParameterPollutionScanner();
    }

    @Test
    public void givenNoFormsWhenScanHttpResponseReceiveThenNoAlertsRaised() throws Exception {
        HttpMessage msg = createHttpMessageFromHtml("");
        scanHttpResponseReceive(msg);
        assertNumberOfAlertsRaised(0);
    }

    @Test
    public void givenFormWithActionAttributeWhenScanHttpResponseReceiveThenNoAlertsRaised() throws Exception {
        HttpMessage msg = createHttpMessageFromHtml("<form action='ActionMan'>");
        scanHttpResponseReceive(msg);
        assertNumberOfAlertsRaised(0);
    }

    @Test
    public void givenFormWithNoActionAttributeWhenScanHttpResponseReceiveThenAlertRaisedAndAlertPopulated() throws Exception {
        HttpMessage msg = createHttpMessageFromHtml("<form />");
        scanHttpResponseReceive(msg);
        Alert alert = getFirstAlertRaised();
        assertEquals(alert.getRisk(), Alert.RISK_MEDIUM);
        assertEquals(alert.getConfidence(), Alert.CONFIDENCE_LOW);
        assertEquals(alert.getUri(), URI);
        assertEquals(alert.getEvidence(), "<form />");
    }

    @Test
    public void givenFormWithValuelessActionAttributeWhenScanHttpResponseReceiveThenAlertRaised() throws Exception {
        HttpMessage msg = createHttpMessageFromHtml("<form action />");
        scanHttpResponseReceive(msg);
        assertNumberOfAlertsRaised(1);
    }

    @Test
    public void givenFormWithEmptyActionAttributeWhenScanHttpResponseReceiveThenAlertRaised() throws Exception {
        HttpMessage msg = createHttpMessageFromHtml("<form action='' />");
        scanHttpResponseReceive(msg);
        assertNumberOfAlertsRaised(1);
    }

    @Test
    public void givenFormWithEmptyAndPopulatedActionAttributesWhenScanHttpResponseReceiveThenAlertRaised() throws Exception {
        HttpMessage msg = createHttpMessageFromHtml("<form action action='ActionMan' />");
        scanHttpResponseReceive(msg);
        assertNumberOfAlertsRaised(1);
    }

    @Test
    public void givenTwoFormsWithNoActionAttributeWhenScanHttpResponseReceiveThenOnlyOneAlertRaised() throws Exception {
        HttpMessage msg = createHttpMessageFromHtml("<form /><form />");
        scanHttpResponseReceive(msg);
        assertNumberOfAlertsRaised(1);
    }

    private Alert getFirstAlertRaised() {
        assertTrue( "Expected Alert but none raised.", alertsRaised.size() > 0 );
        return alertsRaised.get(0);
    }

    private void assertNumberOfAlertsRaised(int expected) {
        assertEquals(expected, alertsRaised.size());
    }

    private void scanHttpResponseReceive(HttpMessage msg) {
        rule.scanHttpResponseReceive(msg, -1, createSource(msg));
    }

    private HttpMessage createHttpMessageFromHtml(String html) throws HttpMalformedHeaderException {
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET " + URI + " HTTP/1.1");
        msg.setResponseHeader("HTTP/1.1 200\r\n");
        msg.setResponseBody(html);
        return msg;
    }
}