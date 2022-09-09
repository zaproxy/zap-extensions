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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.time.Instant;
import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.commonlib.CommonAlertTag;

class TimestampDisclosureScanRuleUnitTest extends PassiveScannerTest<TimestampDisclosureScanRule> {

    @Override
    protected TimestampDisclosureScanRule createScanner() {
        return new TimestampDisclosureScanRule();
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        int cwe = rule.getCweId();
        int wasc = rule.getWascId();
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(cwe, is(equalTo(200)));
        assertThat(wasc, is(equalTo(13)));
        assertThat(tags.size(), is(equalTo(2)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A01_BROKEN_AC.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A03_DATA_EXPOSED.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A01_BROKEN_AC.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A01_BROKEN_AC.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A03_DATA_EXPOSED.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A03_DATA_EXPOSED.getValue())));
    }

    @Test
    void verifyIgnoredHeadersListAsExpected() {
        // Given / When
        List<String> ignoreList =
                Arrays.asList(TimestampDisclosureScanRule.RESPONSE_HEADERS_TO_IGNORE);
        // Then
        assertEquals(8, ignoreList.size());
    }

    private static Stream<Arguments> headersToIgnoreSource() {
        return Arrays.stream(TimestampDisclosureScanRule.RESPONSE_HEADERS_TO_IGNORE)
                .map(Arguments::of);
    }

    @ParameterizedTest
    @MethodSource("headersToIgnoreSource")
    void shouldNotRaiseAlertOnIgnorableHeaders(String header) throws Exception {
        // Given
        HttpMessage msg = createMessage("");
        // This creates a header that would be Alerted upon if not ignored
        // It does not necessarily create a header with realistic content
        String headerToTest = header + ": 2147483647";
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n" + "Server: Apache-Coyote/1.1\r\n" + headerToTest + "\r\n");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(0, alertsRaised.size());
    }

    @ParameterizedTest
    @ValueSource(strings = {"00000000", "000000000", "0000000000"})
    void shouldNotRaiseAlertOnZeroValues(String value) throws Exception {
        // Given
        HttpMessage msg = createMessage(value);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(0, alertsRaised.size());
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "0.33333333%",
                "0.33333333em",
                "0.33333333rem",
                "1.1592500000000001",
                "000000000000000000000000000000001",
                "a{color:#00000042!important;background-color:transparent!important}",
                "111111111",
                "222222222",
                "999999999",
                "0000000000",
                "1234567890",
                "1111111111",
                "2147483648",
                "2222222222",
                "3333333333",
                "9876543210",
                "10000000000",
            })
    void shouldNotRaiseAlertOnUnlikelyValues(String value) throws Exception {
        // Given
        HttpMessage msg = createMessage(value);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(0, alertsRaised.size());
    }

    @Test
    void shouldRaiseAlertOnValidCurrentTimestamp() throws Exception {
        // Given
        String now =
                String.valueOf(System.currentTimeMillis()).substring(0, 10); // 10 Digit precision
        HttpMessage msg = createMessage(now);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(1, alertsRaised.size());
        assertEquals(now, alertsRaised.get(0).getEvidence());
    }

    @Test
    void shouldRaiseAlertOnValidCurrentTimestampAtHighThreshold() throws Exception {
        // Given
        String now =
                String.valueOf(System.currentTimeMillis()).substring(0, 10); // 10 Digit precision
        HttpMessage msg = createMessage(now);
        rule.setAlertThreshold(AlertThreshold.HIGH);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(1, alertsRaised.size());
        assertEquals(now, alertsRaised.get(0).getEvidence());
    }

    @Test
    void shouldRaiseAlertOnTimeStampWhenWithinPastYear() throws Exception {
        // Given
        Instant testDate = ZonedDateTime.now().minusMonths(6).toInstant();
        String strTestDate = String.valueOf(testDate.getEpochSecond());
        HttpMessage msg = createMessage(strTestDate);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(1, alertsRaised.size());
        assertEquals(strTestDate, alertsRaised.get(0).getEvidence());
    }

    @Test
    void shouldRaiseAlertOnTimeStampWhenWithinPastYearAtHighThreshold() throws Exception {
        // Given
        Instant testDate = ZonedDateTime.now().minusMonths(6).toInstant();
        String strTestDate = String.valueOf(testDate.getEpochSecond());
        HttpMessage msg = createMessage(strTestDate);
        rule.setAlertThreshold(AlertThreshold.HIGH);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(1, alertsRaised.size());
        assertEquals(strTestDate, alertsRaised.get(0).getEvidence());
    }

    @Test
    void shouldRaiseAlertOnTimeStampWhenWithinNextYear() throws Exception {
        // Given
        Instant testDate = ZonedDateTime.now().plusMonths(6).toInstant();
        String strTestDate = String.valueOf(testDate.getEpochSecond());
        HttpMessage msg = createMessage(strTestDate);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(1, alertsRaised.size());
        assertEquals(strTestDate, alertsRaised.get(0).getEvidence());
    }

    @Test
    void shouldRaiseAlertOnTimeStampWhenWithinNextYearAtHighThreshold() throws Exception {
        // Given
        Instant testDate = ZonedDateTime.now().plusMonths(6).toInstant();
        String strTestDate = String.valueOf(testDate.getEpochSecond());
        HttpMessage msg = createMessage(strTestDate);
        rule.setAlertThreshold(AlertThreshold.HIGH);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(1, alertsRaised.size());
        assertEquals(strTestDate, alertsRaised.get(0).getEvidence());
    }

    @Test
    void shouldRaiseAlertOnTimeStampWhenThreeYearsAgo() throws Exception {
        // Given
        Instant testDate = ZonedDateTime.now().minusYears(3).toInstant();
        String strTestDate = String.valueOf(testDate.getEpochSecond());
        HttpMessage msg = createMessage(strTestDate);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(1, alertsRaised.size());
        assertEquals(strTestDate, alertsRaised.get(0).getEvidence());
    }

    @Test
    void shouldNotRaiseAlertOnTimeStampWhenThreeYearsAgoAtHighThreshold() throws Exception {
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
    void shouldRaiseAlertOnTimeStampWhenThreeYearsFromNow() throws Exception {
        // Given
        Instant testDate = ZonedDateTime.now().plusYears(3).toInstant();
        String strTestDate = String.valueOf(testDate.getEpochSecond());
        HttpMessage msg = createMessage(strTestDate);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(1, alertsRaised.size());
        assertEquals(strTestDate, alertsRaised.get(0).getEvidence());
    }

    @Test
    void shouldNotRaiseAlertOnTimeStampWhenThreeYearsFromNowAtHighThreshold() throws Exception {
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
    void shouldRaiseAlertOnTimeStampWhenFarInThePast() throws Exception {
        // Given
        Instant testDate = ZonedDateTime.now().minusYears(9).toInstant();
        String strTestDate = String.valueOf(testDate.getEpochSecond());
        HttpMessage msg = createMessage(strTestDate);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(1, alertsRaised.size());
        assertEquals(strTestDate, alertsRaised.get(0).getEvidence());
    }

    @Test
    void shouldRaiseAlertOnTimeStampWhenVeryFarInThePastAtLowThreshold() throws Exception {
        // Given
        String strTestDate = String.valueOf(1000000000L);
        HttpMessage msg = createMessage(strTestDate);
        rule.setAlertThreshold(AlertThreshold.LOW);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(1, alertsRaised.size());
    }

    @Test
    void shouldNotRaiseAlertOnTimeStampWhenFarInThePastAtHighThreshold() throws Exception {
        // Given
        Instant testDate = ZonedDateTime.now().minusYears(9).toInstant();
        String strTestDate = String.valueOf(testDate.getEpochSecond());
        HttpMessage msg = createMessage(strTestDate);
        rule.setAlertThreshold(AlertThreshold.HIGH);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(0, alertsRaised.size());
    }

    @Test
    void shouldRaiseAlertOnTimeStampWhenFarInTheFuture() throws Exception {
        long epochY2038 = 2147483647L;
        Instant eventHorizon = ZonedDateTime.now().plusYears(10).toInstant();

        long future =
                (eventHorizon.isBefore(new Date(TimeUnit.SECONDS.toMillis(epochY2038)).toInstant())
                                ? eventHorizon.getEpochSecond()
                                : epochY2038)
                        - 1;
        // Given
        String strTestDate = String.valueOf(future);
        HttpMessage msg = createMessage(strTestDate);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(1, alertsRaised.size());
        assertEquals(strTestDate, alertsRaised.get(0).getEvidence());
    }

    @Test
    void shouldNotRaiseAlertOnTimeStampWhenFarInTheFutureAtHighThreshold() throws Exception {
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
    void shouldRaiseTwoAlertsWhenOneOfTwoTimeStampWithinNextYear() throws Exception {
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
        assertEquals(strTestDate, alertsRaised.get(0).getEvidence());
        assertEquals(strTestDate2, alertsRaised.get(1).getEvidence());
    }

    @Test
    void shouldRaiseOneAlertWhenOneOfTwoTimeStampWithinNextYearAtHighThreshold() throws Exception {
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
        assertEquals(strTestDate, alertsRaised.get(0).getEvidence());
    }

    @Test
    void shouldRaiseTwoAlertsWhenOneOfTwoTimeStampWithinPastYear() throws Exception {
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
        assertEquals(strTestDate, alertsRaised.get(0).getEvidence());
        assertEquals(strTestDate2, alertsRaised.get(1).getEvidence());
    }

    @Test
    void shouldRaiseOneAlertWhenOneOfTwoTimeStampWithinPastYearAtHighThreshold() throws Exception {
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
        assertEquals(strTestDate2, alertsRaised.get(0).getEvidence());
    }

    @ParameterizedTest
    @ValueSource(strings = {"font.woff", "font.woff2", "font.ttf", "font.otf"})
    void shouldNotRaiseAlertOnValidTimeStampInFontUrlRequest(String fileName) throws Exception {
        // Given
        Instant testDate = ZonedDateTime.now().minusMonths(6).toInstant();
        String strTestDate = String.valueOf(testDate.getEpochSecond());
        HttpMessage msg = createMessage(strTestDate);
        msg.getRequestHeader().setURI(new URI("http://example.com/" + fileName, false));
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(0, alertsRaised.size());
    }

    @ParameterizedTest
    @ValueSource(strings = {"font/ttf", "font/otf", "font/woff", "font/woff2"})
    void shouldNotRaiseAlertOnValidTimeStampWhenInFontResponse(String type) throws Exception {
        // Given
        Instant testDate = ZonedDateTime.now().minusMonths(6).toInstant();
        String strTestDate = String.valueOf(testDate.getEpochSecond());
        HttpMessage msg = createMessage(strTestDate);
        msg.getResponseHeader().setHeader(HttpHeader.CONTENT_TYPE, type);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(0, alertsRaised.size());
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
