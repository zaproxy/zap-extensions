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
package org.zaproxy.zap.extension.pscanrulesBeta;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.params.provider.Arguments.arguments;

import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;

/** Unit test for {@link PiiScanRule}. */
public class PiiScanRuleUnitTest extends PassiveScannerTest<PiiScanRule> {

    @Override
    protected PiiScanRule createScanner() {
        return new PiiScanRule();
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
    public void shouldRaiseAlertWhenCreditCardIsDetected(String cardName, String cardNumber)
            throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
        msg.setResponseHeader("HTTP/1.1 200 OK\r\n" + "Server: Apache-Coyote/1.1\r\n");
        msg.setResponseBody("{\"cc\": \"" + cardNumber + "\"}");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), is(1));
        assertThat(alertsRaised.get(0).getName(), equalTo("PII Disclosure"));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo(cardNumber.replaceAll("\\s+", "")));
    }

    @Test
    public void shouldNotFailWithStackOverflowErrorWhenScanningResponseWithManyNumbers()
            throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
        msg.setResponseBody(numbers(15000));
        // When / Then
        assertDoesNotThrow(() -> scanHttpResponseReceive(msg));
    }

    @Test
    public void shouldNotRaiseAlertWhenNumberDoesntHaveWordBoundaries() throws Exception {
        // Given
        String cardNumber = "8.46786664623715e-47";
        HttpMessage msg = createMsg(cardNumber);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), is(0));
    }

    @Test
    public void shouldNotRaiseAlertInLeadingLongExponentNumbers() throws Exception {
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
    public void shouldNotRaiseAlertInTrailingLongNegativeExponentNumbers() throws Exception {
        // Given
        String content = "2.41111111111111111e-2"; // Visa - Extra digit before e
        HttpMessage msg = createMsg(content);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), is(0));
    }

    @Test
    public void shouldNotRaiseAlertInTrailingLongPositiveExponentNumbers() throws Exception {
        // Given
        String content = "2.41111111111111111e2"; // Visa - Extra digit before e
        HttpMessage msg = createMsg(content);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), is(0));
    }

    @Test
    public void shouldNotRaiseAlertInPositiveExponentNumbers() throws Exception {
        // Given
        String content = "2.4111111111111111e2"; // Visa - Valid ahead of exponent
        HttpMessage msg = createMsg(content);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), is(0));
    }

    @Test
    public void shouldRaiseAlertInPlausiblePeriodDelimitedContent() throws Exception {
        // Given
        String content = "1121.4111111111111111.John Smith.808"; // Visa
        HttpMessage msg = createMsg(content);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), is(1));
    }

    private HttpMessage createMsg(String cardNumber) throws HttpMalformedHeaderException {
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
        msg.setResponseHeader("HTTP/1.1 200 OK\r\n" + "Server: Apache-Coyote/1.1\r\n");
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
