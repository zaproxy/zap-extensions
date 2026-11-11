/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.zap.extension.ascanrulesAlpha;

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;

import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import java.math.BigDecimal;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.zap.testutils.NanoServerHandler;

/** Unit test for {@link PaymentAmountManipulationScanRule}. */
class PaymentAmountManipulationScanRuleUnitTest
        extends ActiveScannerTest<PaymentAmountManipulationScanRule> {

    private static final String PATH = "/payments";

    @Override
    protected PaymentAmountManipulationScanRule createScanner() {
        return new PaymentAmountManipulationScanRule();
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        int cwe = rule.getCweId();
        int wasc = rule.getWascId();
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(cwe, is(equalTo(20)));
        assertThat(wasc, is(equalTo(20)));
        assertThat(tags.size(), is(equalTo(4)));
        assertThat(
                tags.get(CommonAlertTag.WSTG_V42_BUSL_01_DATA_VALIDATION.getTag()),
                is(equalTo(CommonAlertTag.WSTG_V42_BUSL_01_DATA_VALIDATION.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2025_A06_INSECURE_DESIGN.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2025_A06_INSECURE_DESIGN.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A04_INSECURE_DESIGN.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A04_INSECURE_DESIGN.getValue())));
        assertThat(tags.containsKey(PolicyTag.PENTEST.getTag()), is(equalTo(true)));
    }

    @Test
    void shouldHaveExpectedExampleAlerts() {
        // Given / When
        List<Alert> alerts = rule.getExampleAlerts();
        // Then
        assertThat(alerts, hasSize(2));
        assertThat(alerts.get(0).getRisk(), is(equalTo(Alert.RISK_HIGH)));
        assertThat(alerts.get(0).getConfidence(), is(equalTo(Alert.CONFIDENCE_MEDIUM)));
        assertThat(alerts.get(0).getEvidence(), is(equalTo("-10.00")));
        assertThat(alerts.get(1).getConfidence(), is(equalTo(Alert.CONFIDENCE_LOW)));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "amount",
                "Amount",
                "AMOUNT",
                "refundAmount",
                "reload_amount",
                "total-amount",
                "orderTotal",
                "order[price]",
                "tip",
                "amt"
            })
    void shouldMatchMoneyParameterNames(String name) {
        assertThat(rule.isMoneyParameter(name), is(true));
    }

    @ParameterizedTest
    @ValueSource(strings = {"note", "id", "subtotal", "amounts", "valued", "currency", "tipping"})
    void shouldNotMatchOtherParameterNames(String name) {
        assertThat(rule.isMoneyParameter(name), is(false));
    }

    @Test
    void shouldUseDefaultMoneyWordsIfNotConfigured() throws Exception {
        // Given
        rule.init(postMessage("amount=10.00"), parent);
        // When / Then
        assertThat(rule.isMoneyParameter("amount"), is(true));
        assertThat(rule.isMoneyParameter("tip"), is(true));
        assertThat(rule.isMoneyParameter("gratuity"), is(false));
    }

    @Test
    void shouldUseConfiguredMoneyWordsInsteadOfDefaults() throws Exception {
        // Given
        rule.getConfig()
                .setProperty(
                        PaymentAmountManipulationScanRule.MONEY_WORDS_CONFIG_KEY,
                        " Gratuity, , remittance ");
        rule.init(postMessage("gratuity=10.00"), parent);
        // When / Then
        assertThat(rule.isMoneyParameter("gratuity"), is(true));
        assertThat(rule.isMoneyParameter("orderRemittance"), is(true));
        assertThat(rule.isMoneyParameter("amount"), is(false));
    }

    @Test
    void shouldFallBackToDefaultMoneyWordsIfConfiguredListIsBlank() throws Exception {
        // Given
        rule.getConfig()
                .setProperty(PaymentAmountManipulationScanRule.MONEY_WORDS_CONFIG_KEY, " , ");
        rule.init(postMessage("amount=10.00"), parent);
        // When / Then
        assertThat(rule.isMoneyParameter("amount"), is(true));
    }

    @ParameterizedTest
    @CsvSource({"10,10", "10.00,10.00", "$1500.50,1500.50", "'1,234.50',1234.50", "-5,-5"})
    void shouldParseDecimalAmounts(String value, String expected) {
        assertThat(
                PaymentAmountManipulationScanRule.parseAmount(value),
                is(equalTo(new BigDecimal(expected))));
    }

    @ParameterizedTest
    @ValueSource(strings = {"abc", "", "10 apples", "1,2", "NaN"})
    void shouldNotParseNonDecimalAmounts(String value) {
        assertThat(PaymentAmountManipulationScanRule.parseAmount(value), is(nullValue()));
    }

    @Test
    void shouldNotAlertIfNegativeAndZeroAreRejected() throws Exception {
        // Given
        AmountHandler handler =
                new AmountHandler(
                        PATH, "amount", PaymentAmountManipulationScanRuleUnitTest::rejectInvalid);
        nano.addHandler(handler);
        rule.setAttackStrength(AttackStrength.LOW);
        rule.init(postMessage("amount=10.00"), parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, is(empty()));
        assertThat(handler.received, contains("-10.00", "0"));
    }

    @Test
    void shouldAlertHighIfNegativeAmountIsEchoed() throws Exception {
        // Given
        nano.addHandler(new AmountHandler(PATH, "amount", AmountHandler::echo));
        rule.setAttackStrength(AttackStrength.LOW);
        rule.init(postMessage("amount=10.00"), parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        Alert alert = alertsRaised.get(0);
        assertThat(alert.getRisk(), is(equalTo(Alert.RISK_HIGH)));
        assertThat(alert.getConfidence(), is(equalTo(Alert.CONFIDENCE_MEDIUM)));
        assertThat(alert.getParam(), is(equalTo("amount")));
        assertThat(alert.getEvidence(), is(equalTo("-10.00")));
        assertThat(alert.getAttack(), is(equalTo("-10.00")));
        assertThat(alert.getAlertRef(), is(equalTo(rule.getId() + "-1")));
    }

    @Test
    void shouldAlertMediumIfOnlyZeroAmountIsEchoed() throws Exception {
        // Given
        nano.addHandler(
                new AmountHandler(
                        PATH,
                        "amount",
                        value ->
                                value.startsWith("-")
                                        ? json(Response.Status.BAD_REQUEST, "{\"error\":1}")
                                        : AmountHandler.echo(value)));
        rule.setAttackStrength(AttackStrength.LOW);
        rule.init(postMessage("amount=10.00"), parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getRisk(), is(equalTo(Alert.RISK_MEDIUM)));
        assertThat(alertsRaised.get(0).getEvidence(), is(equalTo("0")));
    }

    @Test
    void shouldAlertOnWeakWordParameterWithPost() throws Exception {
        // Given
        nano.addHandler(new AmountHandler(PATH, "tip", AmountHandler::echo));
        rule.setAttackStrength(AttackStrength.LOW);
        rule.init(postMessage("tip=5"), parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getEvidence(), is(equalTo("-5")));
    }

    @Test
    void shouldNotSendAnythingIfParameterNameDoesNotMatch() throws Exception {
        // Given
        AmountHandler handler = new AmountHandler(PATH, "note", AmountHandler::echo);
        nano.addHandler(handler);
        rule.init(postMessage("note=10.00"), parent);
        // When
        rule.scan();
        // Then
        assertThat(countMessagesSent, is(equalTo(0)));
        assertThat(alertsRaised, is(empty()));
    }

    @Test
    void shouldNotSendAnythingIfValueIsNotDecimal() throws Exception {
        // Given
        nano.addHandler(new AmountHandler(PATH, "amount", AmountHandler::echo));
        rule.init(postMessage("amount=abc"), parent);
        // When
        rule.scan();
        // Then
        assertThat(countMessagesSent, is(equalTo(0)));
    }

    @Test
    void shouldNotSendAnythingForGetRequest() throws Exception {
        // Given
        nano.addHandler(new AmountHandler("/products", "price", AmountHandler::echo));
        HttpMessage msg = getHttpMessage("GET", "/products?price=10", "{\"price\":10}");
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(countMessagesSent, is(equalTo(0)));
        assertThat(alertsRaised, is(empty()));
    }

    @ParameterizedTest
    @ValueSource(ints = {302, 400, 404, 500})
    void shouldNotSendAnythingIfOriginalResponseWasNotSuccessful(int status) throws Exception {
        // Given
        nano.addHandler(new AmountHandler(PATH, "amount", AmountHandler::echo));
        HttpMessage msg = postMessage("amount=10.00");
        msg.getResponseHeader().setStatusCode(status);
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(countMessagesSent, is(equalTo(0)));
    }

    @Test
    void shouldAlertLowConfidenceIfAlteredAmountGetsSimilarResponseAndControlDoesNot()
            throws Exception {
        // Given
        AmountHandler handler =
                new AmountHandler(
                        PATH,
                        "amount",
                        value ->
                                PaymentAmountManipulationScanRule.parseAmount(value) == null
                                        ? json(Response.Status.BAD_REQUEST, "{\"error\":1}")
                                        : json(Response.Status.OK, BASELINE_BODY));
        nano.addHandler(handler);
        rule.setAttackStrength(AttackStrength.LOW);
        rule.init(postMessage("amount=10.00"), parent);
        // When
        rule.scan();
        // Then
        assertThat(handler.received, contains("-10.00", "0", "notanumber"));
        assertThat(alertsRaised, hasSize(1));
        Alert alert = alertsRaised.get(0);
        assertThat(alert.getConfidence(), is(equalTo(Alert.CONFIDENCE_LOW)));
        assertThat(alert.getRisk(), is(equalTo(Alert.RISK_HIGH)));
        assertThat(alert.getEvidence(), is(equalTo("-10.00")));
        assertThat(alert.getAlertRef(), is(equalTo(rule.getId() + "-2")));
    }

    @Test
    void shouldNotAlertIfControlRequestGetsSimilarResponse() throws Exception {
        // Given
        AmountHandler handler =
                new AmountHandler(PATH, "amount", value -> json(Response.Status.OK, BASELINE_BODY));
        nano.addHandler(handler);
        rule.setAttackStrength(AttackStrength.LOW);
        rule.init(postMessage("amount=10.00"), parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, is(empty()));
        assertThat(handler.received, contains("-10.00", "0", "notanumber"));
    }

    @Test
    void shouldSendExpectedPayloadsAtHighStrength() throws Exception {
        // Given
        AmountHandler handler =
                new AmountHandler(
                        PATH, "amount", PaymentAmountManipulationScanRuleUnitTest::rejectInvalid);
        nano.addHandler(handler);
        rule.setAttackStrength(AttackStrength.HIGH);
        rule.init(postMessage("amount=10.00"), parent);
        // When
        rule.scan();
        // Then
        assertThat(handler.received, contains("-10.00", "0", "10.00001", "999999999999"));
    }

    @ParameterizedTest
    @CsvSource({"10.00,10.00001", "10,10.001", "'10.',10.001", "'1,234.50','1,234.50001'", "1e3,"})
    void shouldBuildExcessPrecisionPayloadForOriginalFormat(String original, String expected)
            throws Exception {
        // Given
        AmountHandler handler =
                new AmountHandler(
                        PATH, "amount", PaymentAmountManipulationScanRuleUnitTest::rejectInvalid);
        nano.addHandler(handler);
        rule.setAttackStrength(AttackStrength.MEDIUM);
        rule.init(
                postMessage("amount=" + URLEncoder.encode(original, StandardCharsets.UTF_8)),
                parent);
        // When
        rule.scan();
        // Then
        assertThat(
                handler.received,
                expected == null
                        ? contains("-" + original, "0", "999999999999")
                        : contains("-" + original, "0", expected, "999999999999"));
    }

    @ParameterizedTest
    @CsvSource({"0,", "-5,0"})
    void shouldSendExpectedPayloadsForZeroAndNegativeOriginals(String original, String expected)
            throws Exception {
        // Given
        AmountHandler handler =
                new AmountHandler(
                        PATH, "amount", PaymentAmountManipulationScanRuleUnitTest::rejectInvalid);
        nano.addHandler(handler);
        rule.setAttackStrength(AttackStrength.LOW);
        rule.init(postMessage("amount=" + original), parent);
        // When
        rule.scan();
        // Then
        assertThat(handler.received, expected == null ? is(empty()) : contains(expected));
    }

    @Test
    void shouldAlertIfNegativeAmountIsEchoedInDifferentNumericFormat() throws Exception {
        // Given
        nano.addHandler(
                new AmountHandler(
                        PATH,
                        "amount",
                        value ->
                                AmountHandler.echo(
                                        PaymentAmountManipulationScanRule.parseAmount(value)
                                                .stripTrailingZeros()
                                                .toPlainString())));
        rule.setAttackStrength(AttackStrength.LOW);
        rule.init(postMessage("amount=10.00"), parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getEvidence(), is(equalTo("-10.00")));
        assertThat(alertsRaised.get(0).getConfidence(), is(equalTo(Alert.CONFIDENCE_MEDIUM)));
    }

    @Test
    void shouldNotAlertIfSimilarResponseDeclaresFailureForAlteredAmounts() throws Exception {
        // Given
        String errorBody = "{\"status\":\"ok\",\"id\":\"p-1\",\"error\":\"invalid amount\"}";
        nano.addHandler(
                new AmountHandler(
                        PATH,
                        "amount",
                        value ->
                                PaymentAmountManipulationScanRule.parseAmount(value) == null
                                        ? json(Response.Status.BAD_REQUEST, "{\"error\":1}")
                                        : json(Response.Status.OK, errorBody)));
        rule.setAttackStrength(AttackStrength.LOW);
        rule.init(postMessage("amount=10.00"), parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, is(empty()));
    }

    @Test
    void shouldNotSendFurtherRequestsOnceStopped() throws Exception {
        // Given
        AmountHandler handler =
                new AmountHandler(
                        PATH,
                        "amount",
                        value -> {
                            parent.stop();
                            return rejectInvalid(value);
                        });
        nano.addHandler(handler);
        rule.setAttackStrength(AttackStrength.HIGH);
        rule.init(postMessage("amount=10.00"), parent);
        // When
        rule.scan();
        // Then
        assertThat(handler.received, contains("-10.00"));
    }

    @Test
    void shouldAlertLowConfidenceIfOnlyExcessPrecisionAmountIsEchoed() throws Exception {
        // Given
        nano.addHandler(
                new AmountHandler(
                        PATH,
                        "amount",
                        value ->
                                value.contains("-") || value.equals("0")
                                        ? rejectInvalid(value)
                                        : AmountHandler.echo(value)));
        rule.setAttackStrength(AttackStrength.MEDIUM);
        rule.init(postMessage("amount=10.00"), parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        Alert alert = alertsRaised.get(0);
        assertThat(alert.getEvidence(), is(equalTo("10.00001")));
        assertThat(alert.getConfidence(), is(equalTo(Alert.CONFIDENCE_LOW)));
    }

    @Test
    void shouldAlertLowConfidenceIfOnlyHugeAmountIsEchoed() throws Exception {
        // Given
        nano.addHandler(
                new AmountHandler(
                        PATH,
                        "amount",
                        value ->
                                value.contains("-") || value.equals("0") || value.equals("10.00001")
                                        ? rejectInvalid(value)
                                        : AmountHandler.echo(value)));
        rule.setAttackStrength(AttackStrength.MEDIUM);
        rule.init(postMessage("amount=10.00"), parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        Alert alert = alertsRaised.get(0);
        assertThat(alert.getEvidence(), is(equalTo("999999999999")));
        assertThat(alert.getConfidence(), is(equalTo(Alert.CONFIDENCE_LOW)));
    }

    @Test
    void shouldAddExcessPrecisionToIntegerAmountAtMediumStrength() throws Exception {
        // Given
        AmountHandler handler =
                new AmountHandler(
                        PATH, "amount", PaymentAmountManipulationScanRuleUnitTest::rejectInvalid);
        nano.addHandler(handler);
        rule.setAttackStrength(AttackStrength.MEDIUM);
        rule.init(postMessage("amount=10"), parent);
        // When
        rule.scan();
        // Then
        assertThat(handler.received, contains("-10", "0", "10.001", "999999999999"));
    }

    @Test
    void shouldAlertHighIfNegativeAmountIsEchoedForJsonBody() throws Exception {
        // Given
        AmountHandler handler = new AmountHandler(PATH, "amount", AmountHandler::echo);
        nano.addHandler(handler);
        rule.setAttackStrength(AttackStrength.LOW);
        rule.init(requestMessage("POST", "application/json", "{\"amount\":10.00}"), parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getRisk(), is(equalTo(Alert.RISK_HIGH)));
        assertThat(alertsRaised.get(0).getEvidence(), is(equalTo("-10.00")));
        assertThat(handler.rawBodies.get(0), is(equalTo("{\"amount\":-10.00}")));
    }

    @Test
    void shouldKeepJsonStringAmountQuotedAndSendControlAsString() throws Exception {
        // Given
        AmountHandler handler =
                new AmountHandler(
                        PATH, "amount", PaymentAmountManipulationScanRuleUnitTest::rejectInvalid);
        nano.addHandler(handler);
        rule.setAttackStrength(AttackStrength.LOW);
        rule.init(requestMessage("POST", "application/json", "{\"amount\":\"10.00\"}"), parent);
        // When
        rule.scan();
        // Then
        assertThat(handler.rawBodies, contains("{\"amount\":\"-10.00\"}", "{\"amount\":\"0\"}"));
    }

    @Test
    void shouldKeepJsonNumberPayloadWithExponentSignUnquoted() throws Exception {
        // Given
        AmountHandler handler =
                new AmountHandler(
                        PATH, "amount", PaymentAmountManipulationScanRuleUnitTest::rejectInvalid);
        nano.addHandler(handler);
        rule.setAttackStrength(AttackStrength.LOW);
        rule.init(requestMessage("POST", "application/json", "{\"amount\":1e+3}"), parent);
        // When
        rule.scan();
        // Then
        assertThat(handler.rawBodies, contains("{\"amount\":-1e+3}", "{\"amount\":0}"));
    }

    @Test
    void shouldKeepJsonNumberInArrayUnquoted() throws Exception {
        // Given
        AmountHandler handler =
                new AmountHandler(
                        PATH, "amount", PaymentAmountManipulationScanRuleUnitTest::rejectInvalid);
        nano.addHandler(handler);
        rule.setAttackStrength(AttackStrength.LOW);
        rule.init(requestMessage("POST", "application/json", "{\"amount\":[10]}"), parent);
        // When
        rule.scan();
        // Then
        assertThat(handler.rawBodies, contains("{\"amount\":[-10]}", "{\"amount\":[0]}"));
    }

    @Test
    void shouldNegateExplicitlyPositiveAmount() throws Exception {
        // Given
        AmountHandler handler =
                new AmountHandler(
                        PATH, "amount", PaymentAmountManipulationScanRuleUnitTest::rejectInvalid);
        nano.addHandler(handler);
        rule.setAttackStrength(AttackStrength.LOW);
        rule.init(postMessage("amount=%2B10"), parent);
        // When
        rule.scan();
        // Then
        assertThat(handler.received, contains("-10", "0"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"PUT", "PATCH", "DELETE"})
    void shouldAlertForOtherStateChangingMethods(String method) throws Exception {
        // Given
        nano.addHandler(new AmountHandler(PATH, "amount", AmountHandler::echo));
        rule.setAttackStrength(AttackStrength.LOW);
        rule.init(
                requestMessage(method, "application/x-www-form-urlencoded", "amount=10.00"),
                parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getEvidence(), is(equalTo("-10.00")));
    }

    @Test
    void shouldNotAlertIfAmountIsAlreadyInOriginalResponse() throws Exception {
        // Given
        String body = "{\"status\":\"ok\",\"amount\":10.00,\"refunded\":-10.00,\"fee\":0}";
        nano.addHandler(new AmountHandler(PATH, "amount", value -> json(Response.Status.OK, body)));
        rule.setAttackStrength(AttackStrength.LOW);
        HttpMessage msg = postMessage("amount=10.00");
        msg.getResponseBody().setBody(body);
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, is(empty()));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "{\"error\":\"amount -10.00 invalid\"}",
                "{\"errors\":[\"amount -10.00 invalid\"]}",
                "{\"errorMessage\":\"amount -10.00 invalid\"}",
                "{\"success\":false,\"amount\":-10.00}",
                "{\"ok\":false,\"amount\":-10.00}",
                "{\"status\":\"Rejected\",\"amount\":-10.00}"
            })
    void shouldNotAlertIfSuccessfulResponseDeclaresFailure(String body) throws Exception {
        // Given
        nano.addHandler(new AmountHandler(PATH, "amount", value -> json(Response.Status.OK, body)));
        rule.setAttackStrength(AttackStrength.LOW);
        rule.init(postMessage("amount=10.00"), parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, is(empty()));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "{\"status\":\"ok\",\"amount\":-10.00}",
                "{\"error\":null,\"amount\":-10.00}",
                "{\"error\":false,\"errors\":[],\"amount\":-10.00}",
                "{\"error\":\"\",\"amount\":-10.00}",
                "{\"success\":true,\"amount\":-10.00}",
                "{\"status\":\"ok\",\"note\":\"not invalid\",\"amount\":-10.00}",
                "{\"data\":{\"error\":\"x\"},\"amount\":-10.00}",
                "amount=-10.00",
                "null",
                "<p>error: amount -10.00</p>"
            })
    void shouldNotTreatOtherBodiesAsErrors(String body) {
        assertThat(PaymentAmountManipulationScanRule.isErrorBody(body), is(false));
    }

    @Test
    void shouldStillAlertIfNonJsonBodyEchoesAmount() throws Exception {
        // Given
        nano.addHandler(
                new AmountHandler(
                        PATH,
                        "amount",
                        value ->
                                newFixedLengthResponse(
                                        Response.Status.OK,
                                        "text/plain",
                                        "error: amount " + value.strip())));
        rule.setAttackStrength(AttackStrength.LOW);
        rule.init(postMessage("amount=10.00"), parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getEvidence(), is(equalTo("-10.00")));
    }

    @Test
    void shouldHaveMiscCategory() {
        assertThat(rule.getCategory(), is(equalTo(Category.MISC)));
    }

    @Test
    void shouldNotMatchNullParameterName() {
        assertThat(rule.isMoneyParameter(null), is(false));
    }

    @Test
    void shouldNotParseNullAmount() {
        assertThat(PaymentAmountManipulationScanRule.parseAmount(null), is(nullValue()));
    }

    @Test
    void shouldNotAlertIfRequestsFail() throws Exception {
        // Given
        rule.setAttackStrength(AttackStrength.LOW);
        rule.init(postMessage("amount=10.00"), parent);
        nano.stop();
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, is(empty()));
    }

    @Test
    void shouldIgnoreNumbersInResponseWhichCannotBeParsed() throws Exception {
        // Given
        nano.addHandler(
                new AmountHandler(
                        PATH,
                        "amount",
                        value ->
                                json(
                                        Response.Status.OK,
                                        "{\"status\":\"ok\",\"id\":1e99999999999,\"amount\":"
                                                + value.strip()
                                                + "}")));
        rule.setAttackStrength(AttackStrength.LOW);
        rule.init(postMessage("amount=10.00"), parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getEvidence(), is(equalTo("-10.00")));
    }

    @Test
    void shouldSkipExcessPrecisionPayloadForExponentOriginalAtHighStrength() throws Exception {
        // Given
        AmountHandler handler =
                new AmountHandler(
                        PATH, "amount", PaymentAmountManipulationScanRuleUnitTest::rejectInvalid);
        nano.addHandler(handler);
        rule.setAttackStrength(AttackStrength.HIGH);
        rule.init(postMessage("amount=1e3"), parent);
        // When
        rule.scan();
        // Then
        assertThat(handler.received, contains("-1e3", "0", "999999999999"));
        assertThat(alertsRaised, is(empty()));
    }

    @Test
    void shouldNotSendHugeAmountPayloadIfOriginalIsHugeAmount() throws Exception {
        // Given
        AmountHandler handler =
                new AmountHandler(
                        PATH, "amount", PaymentAmountManipulationScanRuleUnitTest::rejectInvalid);
        nano.addHandler(handler);
        rule.setAttackStrength(AttackStrength.MEDIUM);
        rule.init(postMessage("amount=999999999999"), parent);
        // When
        rule.scan();
        // Then
        assertThat(handler.received, contains("-999999999999", "0", "999999999999.001"));
    }

    @Test
    void shouldNotSendHugeAmountPayloadIfOriginalIsEquivalentHugeAmount() throws Exception {
        // Given
        AmountHandler handler =
                new AmountHandler(
                        PATH, "amount", PaymentAmountManipulationScanRuleUnitTest::rejectInvalid);
        nano.addHandler(handler);
        rule.setAttackStrength(AttackStrength.MEDIUM);
        rule.init(postMessage("amount=999999999999.00"), parent);
        // When
        rule.scan();
        // Then
        assertThat(handler.received, contains("-999999999999.00", "0", "999999999999.00001"));
    }

    @Test
    void shouldNotSendControlIfStoppedAfterPayloads() throws Exception {
        // Given
        AmountHandler handler =
                new AmountHandler(
                        PATH,
                        "amount",
                        value -> {
                            if ("0".equals(value)) {
                                parent.stop();
                            }
                            return json(Response.Status.OK, BASELINE_BODY);
                        });
        nano.addHandler(handler);
        rule.setAttackStrength(AttackStrength.LOW);
        rule.init(postMessage("amount=10.00"), parent);
        // When
        rule.scan();
        // Then
        assertThat(handler.received, contains("-10.00", "0"));
        assertThat(alertsRaised, is(empty()));
    }

    @Test
    void shouldAlertIfControlGetsSuccessfulButDifferentResponse() throws Exception {
        // Given
        AmountHandler handler =
                new AmountHandler(
                        PATH,
                        "amount",
                        value ->
                                PaymentAmountManipulationScanRule.parseAmount(value) == null
                                        ? json(Response.Status.OK, "{\"unrelated\":\"page\"}")
                                        : json(Response.Status.OK, BASELINE_BODY));
        nano.addHandler(handler);
        rule.setAttackStrength(AttackStrength.LOW);
        rule.init(postMessage("amount=10.00"), parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getConfidence(), is(equalTo(Alert.CONFIDENCE_LOW)));
    }

    private static final String BASELINE_BODY =
            "{\"status\":\"ok\",\"id\":\"p-1\",\"amount\":10.00}";

    private HttpMessage postMessage(String requestBody) throws Exception {
        return requestMessage("POST", "application/x-www-form-urlencoded", requestBody);
    }

    private HttpMessage requestMessage(String method, String contentType, String requestBody)
            throws Exception {
        HttpMessage msg = getHttpMessage(method, "application/json", PATH, BASELINE_BODY);
        msg.getRequestHeader().setHeader(HttpHeader.CONTENT_TYPE, contentType);
        msg.setRequestBody(requestBody);
        msg.getRequestHeader().setContentLength(msg.getRequestBody().length());
        return msg;
    }

    private static Response json(Response.IStatus status, String body) {
        return newFixedLengthResponse(status, "application/json", body);
    }

    private static Response rejectInvalid(String value) {
        return json(Response.Status.BAD_REQUEST, "{\"error\":\"invalid amount\"}");
    }

    private static class AmountHandler extends NanoServerHandler {

        private final String param;
        private final Function<String, Response> responder;
        final List<String> received = new ArrayList<>();
        final List<String> rawBodies = new ArrayList<>();

        AmountHandler(String path, String param, Function<String, Response> responder) {
            super(path);
            this.param = param;
            this.responder = responder;
        }

        static Response echo(String value) {
            return json(
                    Response.Status.OK,
                    "{\"status\":\"ok\",\"id\":\"p-1\",\"amount\":" + value.strip() + "}");
        }

        @Override
        protected Response serve(IHTTPSession session) {
            String body = getBody(session);
            rawBodies.add(body);
            String value = formValue(body);
            if (value == null) {
                value = jsonValue(body);
            }
            if (value == null) {
                value = getFirstParamValue(session, param);
            }
            received.add(value);
            return responder.apply(value == null ? "" : value);
        }

        private String jsonValue(String body) {
            Matcher matcher =
                    Pattern.compile("\"" + param + "\"\\s*:\\s*\"?([^\",}]*)\"?").matcher(body);
            return matcher.find() ? matcher.group(1) : null;
        }

        private String formValue(String body) {
            for (String pair : body.split("&")) {
                String[] kv = pair.split("=", 2);
                if (kv.length == 2
                        && URLDecoder.decode(kv[0], StandardCharsets.UTF_8).equals(param)) {
                    return URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
                }
            }
            return null;
        }
    }
}
