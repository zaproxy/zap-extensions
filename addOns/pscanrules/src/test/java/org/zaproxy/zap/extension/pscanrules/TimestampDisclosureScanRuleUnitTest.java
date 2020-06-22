/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2017 The ZAP Development Team
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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.time.ZonedDateTime;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;

public class TimestampDisclosureScanRuleUnitTest
        extends PassiveScannerTest<TimestampDisclosureScanRule> {

    @Override
    protected TimestampDisclosureScanRule createScanner() {
        return new TimestampDisclosureScanRule();
    }

    @Test
    public void shouldNotRaiseAlertOnSTSHeader() throws Exception {
        // Given
        HttpMessage msg = createMessage("");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Strict-Transport-Security: max-age=15552000; includeSubDomains\r\n");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(0, alertsRaised.size());
    }

    @Test
    public void shouldRaiseAlertOnValidCurrentTimestamp() throws Exception {
        // Given
        String now =
                String.valueOf(System.currentTimeMillis()).substring(0, 10); // 10 Digit precision
        HttpMessage msg = createMessage(now);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(1, alertsRaised.size());
        assertTrue(alertsRaised.get(0).getEvidence().equals(now));
    }

    @Test
    public void shouldRaiseAlertOnValidCurrentTimestampAtHighThreshold() throws Exception {
        // Given
        String now =
                String.valueOf(System.currentTimeMillis()).substring(0, 10); // 10 Digit precision
        HttpMessage msg = createMessage(now);
        rule.setAlertThreshold(AlertThreshold.HIGH);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(1, alertsRaised.size());
        assertTrue(alertsRaised.get(0).getEvidence().equals(now));
    }

    @Test
    public void shouldRaiseAlertOnTimeStampWhenWithinPastYear() throws Exception {
        // Given
        Instant testDate = ZonedDateTime.now().minusMonths(6).toInstant();
        String strTestDate = String.valueOf(testDate.getEpochSecond());
        HttpMessage msg = createMessage(strTestDate);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(1, alertsRaised.size());
        assertTrue(alertsRaised.get(0).getEvidence().equals(strTestDate));
    }

    @Test
    public void shouldRaiseAlertOnTimeStampWhenWithinPastYearAtHighThreshold() throws Exception {
        // Given
        Instant testDate = ZonedDateTime.now().minusMonths(6).toInstant();
        String strTestDate = String.valueOf(testDate.getEpochSecond());
        HttpMessage msg = createMessage(strTestDate);
        rule.setAlertThreshold(AlertThreshold.HIGH);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(1, alertsRaised.size());
        assertTrue(alertsRaised.get(0).getEvidence().equals(strTestDate));
    }

    @Test
    public void shouldRaiseAlertOnTimeStampWhenWithinNextYear() throws Exception {
        // Given
        Instant testDate = ZonedDateTime.now().plusMonths(6).toInstant();
        String strTestDate = String.valueOf(testDate.getEpochSecond());
        HttpMessage msg = createMessage(strTestDate);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(1, alertsRaised.size());
        assertTrue(alertsRaised.get(0).getEvidence().equals(strTestDate));
    }

    @Test
    public void shouldRaiseAlertOnTimeStampWhenWithinNextYearAtHighThreshold() throws Exception {
        // Given
        Instant testDate = ZonedDateTime.now().plusMonths(6).toInstant();
        String strTestDate = String.valueOf(testDate.getEpochSecond());
        HttpMessage msg = createMessage(strTestDate);
        rule.setAlertThreshold(AlertThreshold.HIGH);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(1, alertsRaised.size());
        assertTrue(alertsRaised.get(0).getEvidence().equals(strTestDate));
    }

    @Test
    public void shouldRaiseAlertOnTimeStampWhenThreeYearsAgo() throws Exception {
        // Given
        Instant testDate = ZonedDateTime.now().minusYears(3).toInstant();
        String strTestDate = String.valueOf(testDate.getEpochSecond());
        HttpMessage msg = createMessage(strTestDate);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(1, alertsRaised.size());
        assertTrue(alertsRaised.get(0).getEvidence().equals(strTestDate));
    }

    @Test
    public void shouldNotRaiseAlertOnTimeStampWhenThreeYearsAgoAtHighThreshold() throws Exception {
        // Given
        Instant testDate = ZonedDateTime.now().minusYears(3).toInstant();
        String strTestDate = String.valueOf(testDate.getEpochSecond());
        HttpMessage msg = createMessage(strTestDate);
        rule.setAlertThreshold(AlertThreshold.HIGH);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(0, alertsRaised.size());
    }

    @Test
    public void shouldRaiseAlertOnTimeStampWhenThreeYearsFromNow() throws Exception {
        // Given
        Instant testDate = ZonedDateTime.now().plusYears(3).toInstant();
        String strTestDate = String.valueOf(testDate.getEpochSecond());
        HttpMessage msg = createMessage(strTestDate);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(1, alertsRaised.size());
        assertTrue(alertsRaised.get(0).getEvidence().equals(strTestDate));
    }

    @Test
    public void shouldNotRaiseAlertOnTimeStampWhenThreeYearsFromNowAtHighThreshold()
            throws Exception {
        // Given
        Instant testDate = ZonedDateTime.now().plusYears(3).toInstant();
        String strTestDate = String.valueOf(testDate.getEpochSecond());
        HttpMessage msg = createMessage(strTestDate);
        rule.setAlertThreshold(AlertThreshold.HIGH);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(0, alertsRaised.size());
    }

    @Test
    public void shouldRaiseAlertOnTimeStampWhenFarInThePast() throws Exception {
        // Given
        String strTestDate = String.valueOf(33333333);
        HttpMessage msg = createMessage(strTestDate);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(1, alertsRaised.size());
        assertTrue(alertsRaised.get(0).getEvidence().equals(strTestDate));
    }

    @Test
    public void shouldNotRaiseAlertOnTimeStampWhenFarInThePastAtHighThreshold() throws Exception {
        // Given
        String strTestDate = String.valueOf(33333333);
        HttpMessage msg = createMessage(strTestDate);
        rule.setAlertThreshold(AlertThreshold.HIGH);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(0, alertsRaised.size());
    }

    @Test
    public void shouldRaiseAlertOnTimeStampWhenFarInTheFuture() throws Exception {
        // Given
        String strTestDate = String.valueOf(2147483647);
        HttpMessage msg = createMessage(strTestDate);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(1, alertsRaised.size());
        assertTrue(alertsRaised.get(0).getEvidence().equals(strTestDate));
    }

    @Test
    public void shouldNotRaiseAlertOnTimeStampWhenFarInTheFutureAtHighThreshold() throws Exception {
        // Given
        String strTestDate = String.valueOf(2147483647);
        HttpMessage msg = createMessage(strTestDate);
        rule.setAlertThreshold(AlertThreshold.HIGH);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(0, alertsRaised.size());
    }

    @Test
    public void shouldRaiseTwoAlertsWhenOneOfTwoTimeStampWithinNextYear() throws Exception {
        // Given
        Instant testDate = ZonedDateTime.now().plusMonths(6).toInstant();
        Instant testDate2 = ZonedDateTime.now().plusMonths(18).toInstant();
        String strTestDate = String.valueOf(testDate.getEpochSecond());
        String strTestDate2 = String.valueOf(testDate2.getEpochSecond());
        HttpMessage msg = createMessage("");
        String body = "{\"date\":" + strTestDate + ",\"endDate\":\"" + strTestDate2 + "\"}";
        msg.setResponseBody(body);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(2, alertsRaised.size());
        assertTrue(alertsRaised.get(0).getEvidence().equals(strTestDate));
        assertTrue(alertsRaised.get(1).getEvidence().equals(strTestDate2));
    }

    @Test
    public void shouldRaiseOneAlertWhenOneOfTwoTimeStampWithinNextYearAtHighThreshold()
            throws Exception {
        // Given
        Instant testDate = ZonedDateTime.now().plusMonths(6).toInstant();
        Instant testDate2 = ZonedDateTime.now().plusMonths(18).toInstant();
        String strTestDate = String.valueOf(testDate.getEpochSecond());
        String strTestDate2 = String.valueOf(testDate2.getEpochSecond());
        HttpMessage msg = createMessage("");
        String body = "{\"date\":" + strTestDate + ",\"endDate:\"" + strTestDate2 + "\"}";
        msg.setResponseBody(body);
        rule.setAlertThreshold(AlertThreshold.HIGH);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(1, alertsRaised.size());
        assertTrue(alertsRaised.get(0).getEvidence().equals(strTestDate));
    }

    @Test
    public void shouldRaiseTwoAlertsWhenOneOfTwoTimeStampWithinPastYear() throws Exception {
        // Given
        Instant testDate = ZonedDateTime.now().minusMonths(18).toInstant();
        Instant testDate2 = ZonedDateTime.now().minusMonths(6).toInstant();
        String strTestDate = String.valueOf(testDate.getEpochSecond());
        String strTestDate2 = String.valueOf(testDate2.getEpochSecond());
        HttpMessage msg = createMessage("");
        String body = "{\"date\":" + strTestDate + ",\"endDate\":\"" + strTestDate2 + "\"}";
        msg.setResponseBody(body);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(2, alertsRaised.size());
        assertTrue(alertsRaised.get(0).getEvidence().equals(strTestDate));
        assertTrue(alertsRaised.get(1).getEvidence().equals(strTestDate2));
    }

    @Test
    public void shouldRaiseOneAlertWhenOneOfTwoTimeStampWithinPastYearAtHighThreshold()
            throws Exception {
        // Given
        Instant testDate = ZonedDateTime.now().minusMonths(18).toInstant();
        Instant testDate2 = ZonedDateTime.now().minusMonths(6).toInstant();
        String strTestDate = String.valueOf(testDate.getEpochSecond());
        String strTestDate2 = String.valueOf(testDate2.getEpochSecond());
        HttpMessage msg = createMessage("");
        String body = "{\"date\":" + strTestDate + ",\"endDate:\"" + strTestDate2 + "\"}";
        msg.setResponseBody(body);
        rule.setAlertThreshold(AlertThreshold.HIGH);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(1, alertsRaised.size());
        assertTrue(alertsRaised.get(0).getEvidence().equals(strTestDate2));
    }

    private static HttpMessage createMessage(String timestamp) throws URIException {
        HttpRequestHeader requestHeader = new HttpRequestHeader();
        requestHeader.setURI(new URI("http://example.com", false));

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(requestHeader);

        String body = "{\"date\":" + timestamp + "}";
        msg.setResponseBody(body);
        return msg;
    }
}
