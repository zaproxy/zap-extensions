/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.params.provider.Arguments.arguments;

import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.zaproxy.addon.commonlib.CommonAlertTag;

/** Unit test for {@link PiiScanRule}. */
class PiiScanRuleUnitTest extends PassiveScannerTest<PiiScanRule> {

    @Override
    protected PiiScanRule createScanner() {
        PiiScanRule rule = new PiiScanRule();
        rule.setAlertThreshold(AlertThreshold.MEDIUM);
        return rule;
    }

    private static Stream<Arguments> cardData() {
        return Stream.of(
                arguments("AmericanExpress", "370695954010459"),
                arguments("AmericanExpress with spaces", "370 6959 5401 0459"),
                arguments("DinersClub", "30538761461899"),
                arguments("Discover", "6011377412263580"),
                arguments("Jcb", "3589738566381370"),
                arguments("Maestro", "6762355337694692"),
                arguments("Mastercard", "5264810966944441"),
                arguments("Mastercard with spaces", "5264 8109 66944441"),
                arguments("Visa", "4716186978544330"),
                arguments("Visa with spaces", "4716 1869 7854 4330"));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("cardData")
    void shouldRaiseAlertWhenCreditCardIsDetected(String cardName, String cardNumber)
            throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Type: application/json \r\n");
        msg.setResponseBody("{\"cc\": \"" + cardNumber + "\"}");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), is(1));
        assertThat(alertsRaised.get(0).getName(), equalTo("PII Disclosure"));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo(cardNumber));
    }

    @Test
    void shouldNotFailWithStackOverflowErrorWhenScanningResponseWithManyNumbers() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
        msg.setResponseBody(numbers(15000));
        // When / Then
        assertDoesNotThrow(() -> scanHttpResponseReceive(msg));
    }

    @Test
    void shouldNotRaiseAlertWhenNumberDoesntHaveWordBoundaries() throws Exception {
        // Given
        String cardNumber = "8.46786664623715e-47";
        HttpMessage msg = createMsg(cardNumber);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), is(0));
    }

    @Test
    void shouldNotRaiseAlertInLeadingLongExponentNumbers() throws Exception {
        // Given
        String content =
                "2.14111111111111111e-2"; // Visa - Extra digit before card number (after decimal)
        HttpMessage msg = createMsg(content);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), is(0));
    }

    @Test
    void shouldNotRaiseAlertInTrailingLongNegativeExponentNumbers() throws Exception {
        // Given
        String content = "2.41111111111111111e-2"; // Visa - Extra digit before e
        HttpMessage msg = createMsg(content);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), is(0));
    }

    @Test
    void shouldNotRaiseAlertInTrailingLongPositiveExponentNumbers() throws Exception {
        // Given
        String content = "2.41111111111111111e2"; // Visa - Extra digit before e
        HttpMessage msg = createMsg(content);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), is(0));
    }

    @Test
    void shouldNotRaiseAlertInPositiveExponentNumbers() throws Exception {
        // Given
        String content = "2.4111111111111111e2"; // Visa - Valid ahead of exponent
        HttpMessage msg = createMsg(content);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), is(0));
    }

    @ParameterizedTest
    @EnumSource(
            value = Plugin.AlertThreshold.class,
            names = {"MEDIUM", "HIGH"})
    void shouldNotRaiseAlertInDecimalNumbers(AlertThreshold alertThreshold) throws Exception {
        // Given
        String content = "2.4111111111111111"; // Visa - Valid ahead of exponent
        HttpMessage msg = createMsg(content);
        // When
        rule.setAlertThreshold(alertThreshold);
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), is(0));
    }

    @Test
    void shouldRaiseAlertInDecimalNumbersAtLowThreshold() throws Exception {
        // Given
        String content = "2.4111111111111111"; // Visa - Valid ahead of exponent
        HttpMessage msg = createMsg(content);
        // When
        rule.setAlertThreshold(AlertThreshold.LOW);
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), is(1));
    }

    @Test
    void shouldRaiseAlertInPlausiblePeriodDelimitedContentAtLowThreshold() throws Exception {
        // Given
        String content = "1121.4111111111111111.John Smith.808"; // Visa
        HttpMessage msg = createMsg(content);
        // When
        rule.setAlertThreshold(AlertThreshold.LOW);
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), is(1));
    }

    @Test
    void shouldRaiseAlertInPlausibleCsvContent() throws Exception {
        // Given
        String content = "1121,4111111111111111,John Smith,808"; // Visa
        HttpMessage msg = createMsg(content);
        // When
        rule.setAlertThreshold(AlertThreshold.LOW);
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), is(1));
    }

    @Test
    void shouldNotRaiseAlertOnCssRequest() throws Exception {
        // Given
        String content = "margin-left:85.36370249136206%";
        HttpMessage msg = createMsg("");
        msg.setResponseBody(
                "body {background-color: powderblue;}\n"
                        + "h1 {color: blue;}\n"
                        + "p {color: red;"
                        + content
                        + "}");
        msg.getRequestHeader().setURI(new URI("https://www.example.com/styles.css", true));
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), is(0));
    }

    @Test
    void shouldNotRaiseAlertOnCssResponse() throws Exception {
        // Given
        String content = "margin-left:85.36370249136206%";
        HttpMessage msg = createMsg("");
        msg.setResponseBody(
                "body {background-color: powderblue;}\n"
                        + "h1 {color: blue;}\n"
                        + "p {color: red;"
                        + content
                        + "}");
        msg.getRequestHeader().setURI(new URI("https://www.example.com/assets/styles", true));
        msg.getResponseHeader().setHeader(HttpResponseHeader.CONTENT_TYPE, "text/css");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), is(0));
    }

    @Test
    void shouldNotRaiseAlertOnImageRequest() throws Exception {
        // Given
        HttpMessage msg = createMsg("4111111111111111");
        msg.getRequestHeader().setURI(new URI("https://www.example.com/image.gif", true));
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), is(0));
    }

    @Test
    void shouldNotRaiseAlertOnImageResponse() throws Exception {
        // Given
        HttpMessage msg = createMsg("4111111111111111");
        msg.getRequestHeader().setURI(new URI("https://www.example.com/assets/image", true));
        msg.getResponseHeader().setHeader(HttpResponseHeader.CONTENT_TYPE, "image/gif");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), is(0));
    }

    @Test
    void shouldNotRaiseAlertOnResponseContainingCcLikeStyleAttribute() throws Exception {
        // Given
        String content = "margin-left:85.36370249136206%";
        HttpMessage msg = createMsg("");
        msg.setResponseBody("<h1 style=\"color:blue;" + content + "\">A Blue Heading</h1>");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), is(0));
    }

    @Test
    void shouldRaiseAlertOnResponseContainingCcStringInAdditionToCcLikeStyleAttribute()
            throws Exception {
        // Given
        String content = "margin-left:85.36370249136206%";
        HttpMessage msg = createMsg("");
        msg.setResponseBody(
                "<h1 style=\"color:blue;"
                        + content
                        + "\">A Blue Heading</h1>\r\nCC: 4111111111111111");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), is(1));
        assertEquals("4111111111111111", alertsRaised.get(0).getEvidence());
    }

    private static Stream<Arguments> provideExtensionsAndThreshold() {
        return Stream.of(
                Arguments.of(".pdf", AlertThreshold.MEDIUM),
                Arguments.of(".pdf", AlertThreshold.HIGH),
                Arguments.of(".PDF", AlertThreshold.MEDIUM),
                Arguments.of(".PDF", AlertThreshold.HIGH));
    }

    @ParameterizedTest
    @MethodSource("provideExtensionsAndThreshold")
    void shouldNotAlertWhenRequestUrlSeemsToBeAPdfFileAtMediumOrHighThreshold(
            String ext, AlertThreshold threshold) throws Exception {
        // Given
        String ccNum = "4111 1111 1111 1111";
        HttpMessage msg = createMsg(ccNum);
        msg.getRequestHeader().setURI(new URI("http://example.com/test" + ext, true));
        rule.setAlertThreshold(threshold);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), is(0));
    }

    @ParameterizedTest
    @ValueSource(strings = {".pdf", ".PDF"})
    void shouldAlertWhenRequestUrlSeemsToBeAPdfFileAndLookingForPdfsAtLowThreshold(String ext)
            throws Exception {
        // Given
        String ccNum = "4111 1111 1111 1111";
        HttpMessage msg = createMsg(ccNum);
        msg.getRequestHeader().setURI(new URI("http://example.com/test" + ext, true));
        rule.setAlertThreshold(AlertThreshold.LOW);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), is(1));
        assertThat(alertsRaised.get(0).getEvidence(), is(equalTo(ccNum)));
    }

    @ParameterizedTest
    @EnumSource(names = {"HIGH", "MEDIUM"})
    void shouldNotAlertWhenResponseSeemsToBeAPdfFileAtMediumOrHighThresholds(
            AlertThreshold threshold) throws Exception {
        // Given
        String ccNum = "4111 1111 1111 1111";
        HttpMessage msg = createMsg(ccNum);
        msg.getRequestHeader().setURI(new URI("http://example.com/generate/", true));
        msg.getResponseHeader().setHeader(HttpResponseHeader.CONTENT_TYPE, "application/pdf");
        rule.setAlertThreshold(threshold);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), is(0));
    }

    @Test
    void shouldAlertWhenResponseSeemsToBeAPdfFileAndLookingForPdfsAtLowThreshold()
            throws Exception {
        // Given
        String ccNum = "4111 1111 1111 1111";
        HttpMessage msg = createMsg(ccNum);
        msg.getRequestHeader().setURI(new URI("http://example.com/generate/", true));
        msg.getResponseHeader().setHeader(HttpResponseHeader.CONTENT_TYPE, "application/pdf");
        rule.setAlertThreshold(AlertThreshold.LOW);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), is(1));
        assertThat(alertsRaised.get(0).getEvidence(), is(equalTo(ccNum)));
    }

    @ParameterizedTest
    @EnumSource(names = {"HIGH", "MEDIUM"})
    void shouldNotRaiseAlertWhenPiiIsInJavascriptContentTypeOnNonLowThreshold(
            AlertThreshold threshold) throws Exception {
        // Given
        String ccNum = "4111 1111 1111 1111";
        HttpMessage msg = createMsg(ccNum);
        msg.getRequestHeader().setURI(new URI("http://example.com/generate/", true));
        msg.getResponseHeader()
                .setHeader(HttpResponseHeader.CONTENT_TYPE, "application/javascript");
        rule.setAlertThreshold(threshold);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), is(0));
    }

    @Test
    void shouldRaiseAlertWhenPiiInJavascriptContentTypeOnLOWThreshold() throws Exception {
        String ccNum = "4111 1111 1111 1111";
        HttpMessage msg = createMsg(ccNum);
        msg.getRequestHeader().setURI(new URI("http://example.com/generate/", true));
        msg.getResponseHeader()
                .setHeader(HttpResponseHeader.CONTENT_TYPE, "application/javascript");
        rule.setAlertThreshold(AlertThreshold.LOW);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), is(1));
    }

    private static Stream<Arguments> provideContentTypeAndThreshold() {
        return Stream.of(
                Arguments.of("application/json", AlertThreshold.MEDIUM),
                Arguments.of("application/json", AlertThreshold.HIGH),
                Arguments.of("application/xml", AlertThreshold.MEDIUM),
                Arguments.of("application/xml", AlertThreshold.HIGH),
                Arguments.of("text/html", AlertThreshold.MEDIUM),
                Arguments.of("text/html", AlertThreshold.HIGH));
    }

    @ParameterizedTest
    @MethodSource("provideContentTypeAndThreshold")
    void shouldRaiseAlertsOnPiiWithHtmlOrJsonOrXmlOnNonLowThreshold(
            String contentType, AlertThreshold threshold) throws Exception {
        String ccNum = "4111 1111 1111 1111";
        HttpMessage msg = createMsg(ccNum);
        msg.getRequestHeader().setURI(new URI("http://example.com/generate/", true));
        msg.getResponseHeader().setHeader(HttpResponseHeader.CONTENT_TYPE, contentType);
        rule.setAlertThreshold(threshold);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), is(1));
    }

    @ParameterizedTest
    @CsvSource({"application/json", "application/xml", "text/plain", "text/html"})
    void shouldRaiseAlertsOnPiiWithTextOrHtmlOrJsonOrXmlOnLowThreshold(String contentType)
            throws Exception {
        String ccNum = "4111 1111 1111 1111";
        HttpMessage msg = createMsg(ccNum);
        msg.getRequestHeader().setURI(new URI("http://example.com/generate/", true));
        msg.getResponseHeader().setHeader(HttpResponseHeader.CONTENT_TYPE, contentType);
        rule.setAlertThreshold(AlertThreshold.LOW);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), is(1));
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
                tags.containsKey(CommonAlertTag.OWASP_2017_A03_DATA_EXPOSED.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A04_INSECURE_DESIGN.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A04_INSECURE_DESIGN.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A03_DATA_EXPOSED.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A03_DATA_EXPOSED.getValue())));
    }

    @Test
    void shouldReturnExampleAlerts() {
        // Given / When
        List<Alert> alerts = rule.getExampleAlerts();
        // Then
        assertThat(alerts.size(), is(equalTo(1)));
        Alert alert = alerts.get(0);
        assertThat(alert.getConfidence(), is(equalTo(Alert.CONFIDENCE_HIGH)));
        assertThat(
                alert.getOtherInfo(),
                is(
                        equalTo(
                                "Credit Card Type detected: Visa\n"
                                        + "Bank Identification Number: 471618\n"
                                        + "Brand: VISA\n"
                                        + "Category: PURCHASING\n"
                                        + "Issuer: U.S. BANK N.A. ND")));
    }

    @Test
    @Override
    public void shouldHaveValidReferences() {
        super.shouldHaveValidReferences();
    }

    private HttpMessage createMsg(String cardNumber) throws HttpMalformedHeaderException {
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Type: text/html \r\n");
        msg.setResponseBody("{\"cc\": \"" + cardNumber + "\"}");
        return msg;
    }

    private static String numbers(int count) {
        StringBuilder strBuilder = new StringBuilder();
        for (int i = 1; i <= count; i++) {
            strBuilder.append(i).append('\n');
        }
        return strBuilder.toString();
    }
}
