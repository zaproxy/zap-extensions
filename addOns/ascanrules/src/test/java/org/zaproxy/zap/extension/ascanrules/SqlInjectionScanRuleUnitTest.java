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
package org.zaproxy.zap.extension.ascanrules;

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.apache.commons.text.StringEscapeUtils.escapeXml10;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;

import fi.iki.elonen.NanoHTTPD;
import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import fi.iki.elonen.NanoHTTPD.Response.Status;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Stream;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.text.StringEscapeUtils;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.parosproxy.paros.core.scanner.AbstractPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;
import org.zaproxy.zap.testutils.NanoServerHandler;
import org.zaproxy.zap.testutils.UrlParamValueHandler;

/** Unit test for {@link SqlInjectionScanRule}. */
class SqlInjectionScanRuleUnitTest extends ActiveScannerTest<SqlInjectionScanRule> {

    @Override
    protected int getRecommendMaxNumberMessagesPerParam(AttackStrength strength) {
        int recommendMax = super.getRecommendMaxNumberMessagesPerParam(strength);
        switch (strength) {
            case LOW:
                return recommendMax + 1;
            case MEDIUM:
            default:
                return recommendMax + 14;
            case HIGH:
                return recommendMax + 25;
            case INSANE:
                return recommendMax + 7;
        }
    }

    @Override
    protected SqlInjectionScanRule createScanner() {
        return new SqlInjectionScanRule();
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        int cwe = rule.getCweId();
        int wasc = rule.getWascId();
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(cwe, is(equalTo(89)));
        assertThat(wasc, is(equalTo(19)));
        assertThat(tags.size(), is(equalTo(10)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A03_INJECTION.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A01_INJECTION.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.WSTG_V42_INPV_05_SQLI.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.API.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.DEV_STD.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.DEV_FULL.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.QA_STD.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.QA_FULL.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.SEQUENCE.getTag()), is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A03_INJECTION.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A03_INJECTION.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A01_INJECTION.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A01_INJECTION.getValue())));
        assertThat(
                tags.get(CommonAlertTag.WSTG_V42_INPV_05_SQLI.getTag()),
                is(equalTo(CommonAlertTag.WSTG_V42_INPV_05_SQLI.getValue())));
    }

    @Test
    void shouldTargetDbTech() {
        // Given
        TechSet techSet = techSet(Tech.Db);
        // When
        boolean targets = rule.targets(techSet);
        // Then
        assertThat(targets, is(equalTo(true)));
    }

    @Test
    void shouldTargetOracleDbTech() {
        // Given
        TechSet techSet = techSet(Tech.Oracle);
        // When
        boolean targets = rule.targets(techSet);
        // Then
        assertThat(targets, is(equalTo(true)));
    }

    @Test
    void shouldNotTargetJustNoSqlDbTech() {
        // Given
        TechSet techSet = techSet(Tech.MongoDB, Tech.CouchDB);
        // When
        boolean targets = rule.targets(techSet);
        // Then
        assertThat(targets, is(equalTo(false)));
    }

    @Test
    void shouldTargetNoSqlPlusMsSqlDbTech() {
        // Given
        TechSet techSet = techSet(Tech.MongoDB, Tech.MsSQL, Tech.CouchDB);
        // When
        boolean targets = rule.targets(techSet);
        // Then
        assertThat(targets, is(equalTo(true)));
    }

    @Test
    void shouldTargetDbChildTechs() {
        // Given
        TechSet techSet = techSet(techsOf(Tech.Db));
        techSet.exclude(Tech.Db);
        // When
        boolean targets = rule.targets(techSet);
        // Then
        assertThat(targets, is(equalTo(true)));
    }

    @Test
    void shouldTargetDbChildTechsWithNonBuiltInTechInstances() {
        // Given
        TechSet techSet = techSet(new Tech(new Tech("Db"), "SomeDb"));
        // When
        boolean targets = rule.targets(techSet);
        // Then
        assertThat(targets, is(equalTo(true)));
    }

    @Test
    void shouldNotTargetNonDbTechs() {
        // Given
        TechSet techSet = techSetWithout(techsOf(Tech.Db));
        // When
        boolean targets = rule.targets(techSet);
        // Then
        assertThat(targets, is(equalTo(false)));
    }

    @Test
    void shouldAlertIfSumExpressionsAreSuccessful() throws Exception {
        // Given
        String param = "id";
        nano.addHandler(
                new ExpressionBasedHandler("/", param, ExpressionBasedHandler.Expression.SUM));
        rule.init(
                getHttpMessage("/?" + param + "=" + ExpressionBasedHandler.Expression.SUM.value),
                parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(greaterThan(1)));
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getEvidence(), is(equalTo("")));
        assertThat(alertsRaised.get(0).getParam(), is(equalTo(param)));
        assertThat(
                alertsRaised.get(0).getAttack(),
                is(equalTo(ExpressionBasedHandler.Expression.SUM.baseExpression)));
        assertThat(alertsRaised.get(0).getRisk(), is(equalTo(Alert.RISK_HIGH)));
        assertThat(alertsRaised.get(0).getConfidence(), is(equalTo(Alert.CONFIDENCE_MEDIUM)));
    }

    @Test
    void shouldAlertIfSumExpressionsAreSuccessfulAndReflectedInResponse() throws Exception {
        // Given
        String param = "id";
        nano.addHandler(
                new ExpressionBasedHandler("/", param, ExpressionBasedHandler.Expression.SUM) {

                    @Override
                    protected String getContent(String value) {
                        return super.getContent(value) + ": " + value;
                    }
                });
        rule.init(
                getHttpMessage("/?" + param + "=" + ExpressionBasedHandler.Expression.SUM.value),
                parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(greaterThan(1)));
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getEvidence(), is(equalTo("")));
        assertThat(alertsRaised.get(0).getParam(), is(equalTo(param)));
        assertThat(
                alertsRaised.get(0).getAttack(),
                is(equalTo(ExpressionBasedHandler.Expression.SUM.baseExpression)));
        assertThat(alertsRaised.get(0).getRisk(), is(equalTo(Alert.RISK_HIGH)));
        assertThat(alertsRaised.get(0).getConfidence(), is(equalTo(Alert.CONFIDENCE_MEDIUM)));
    }

    @Test
    void shouldNotAlertIfSumConfirmationExpressionIsNotSuccessful() throws Exception {
        // Given
        String param = "id";
        nano.addHandler(
                new ExpressionBasedHandler(
                        "/", param, ExpressionBasedHandler.Expression.SUM, true));
        rule.init(
                getHttpMessage("/?" + param + "=" + ExpressionBasedHandler.Expression.SUM.value),
                parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(greaterThan(1)));
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldNotAlertIfSumConfirmationExpressionIsNotSuccessfulAndIsReflectedInResponse()
            throws Exception {
        // Given
        String param = "id";
        nano.addHandler(
                new ExpressionBasedHandler(
                        "/",
                        param,
                        ExpressionBasedHandler.Expression.SUM,
                        true,
                        ExpressionBasedHandler.Expression.SUM.confirmationExpression));
        rule.init(
                getHttpMessage("/?" + param + "=" + ExpressionBasedHandler.Expression.SUM.value),
                parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(greaterThan(1)));
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldAlertIfMultExpressionsAreSuccessful() throws Exception {
        // Given
        String param = "id";
        nano.addHandler(
                new ExpressionBasedHandler("/", param, ExpressionBasedHandler.Expression.MULT));
        rule.init(
                getHttpMessage("/?" + param + "=" + ExpressionBasedHandler.Expression.MULT.value),
                parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(greaterThan(1)));
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getEvidence(), is(equalTo("")));
        assertThat(alertsRaised.get(0).getParam(), is(equalTo(param)));
        assertThat(
                alertsRaised.get(0).getAttack(),
                is(equalTo(ExpressionBasedHandler.Expression.MULT.baseExpression)));
        assertThat(alertsRaised.get(0).getRisk(), is(equalTo(Alert.RISK_HIGH)));
        assertThat(alertsRaised.get(0).getConfidence(), is(equalTo(Alert.CONFIDENCE_MEDIUM)));
    }

    @Test
    void shouldAlertIfMultExpressionsAreSuccessfulAndReflectedInResponse() throws Exception {
        // Given
        String param = "id";
        nano.addHandler(
                new ExpressionBasedHandler("/", param, ExpressionBasedHandler.Expression.MULT) {

                    @Override
                    protected String getContent(String value) {
                        return super.getContent(value) + ": " + value;
                    }
                });
        rule.init(
                getHttpMessage("/?" + param + "=" + ExpressionBasedHandler.Expression.MULT.value),
                parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(greaterThan(1)));
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getEvidence(), is(equalTo("")));
        assertThat(alertsRaised.get(0).getParam(), is(equalTo(param)));
        assertThat(
                alertsRaised.get(0).getAttack(),
                is(equalTo(ExpressionBasedHandler.Expression.MULT.baseExpression)));
        assertThat(alertsRaised.get(0).getRisk(), is(equalTo(Alert.RISK_HIGH)));
        assertThat(alertsRaised.get(0).getConfidence(), is(equalTo(Alert.CONFIDENCE_MEDIUM)));
    }

    @Test
    void shouldNotAlertIfMultConfirmationExpressionIsNotSuccessful() throws Exception {
        // Given
        String param = "id";
        nano.addHandler(
                new ExpressionBasedHandler(
                        "/", param, ExpressionBasedHandler.Expression.MULT, true));
        rule.init(
                getHttpMessage("/?" + param + "=" + ExpressionBasedHandler.Expression.MULT.value),
                parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(greaterThan(1)));
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldNotAlertIfMultConfirmationExpressionIsNotSuccessfulAndReflectedInResponse()
            throws Exception {
        // Given
        String param = "id";
        nano.addHandler(
                new ExpressionBasedHandler(
                        "/",
                        param,
                        ExpressionBasedHandler.Expression.MULT,
                        true,
                        ExpressionBasedHandler.Expression.MULT.confirmationExpression));
        rule.init(
                getHttpMessage("/?" + param + "=" + ExpressionBasedHandler.Expression.MULT.value),
                parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(greaterThan(1)));
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldNotAlertIfConfirmationIsDifferentStatusCode() throws Exception {
        // Given
        final String param = "id";
        final String normalValue = "1";
        final String modifiedValue = "3-2";
        final String confirmValue = "4-2";

        Map<String, Supplier<Response>> paramValueToResponseMap = new HashMap<>();
        paramValueToResponseMap.put(
                normalValue,
                () -> {
                    final Response response =
                            newFixedLengthResponse(
                                    Status.OK, NanoHTTPD.MIME_HTML, "Some content: ");
                    return response;
                });
        paramValueToResponseMap.put(
                modifiedValue,
                () -> {
                    final Response response =
                            newFixedLengthResponse(
                                    Status.OK, NanoHTTPD.MIME_HTML, "Some content: ");
                    return response;
                });
        paramValueToResponseMap.put(
                confirmValue,
                () ->
                        newFixedLengthResponse(
                                Status.NOT_FOUND, NanoHTTPD.MIME_HTML, "404 Not Found"));
        ControlledStatusCodeHandler handler =
                new ControlledStatusCodeHandler(param, paramValueToResponseMap);
        nano.addHandler(handler);
        rule.init(getHttpMessage("/?" + param + "=" + normalValue), parent);

        // When
        rule.scan();

        // Then
        assertThat(httpMessagesSent, hasSize(greaterThan(1)));
        assertThat(alertsRaised, hasSize(0));
    }

    static final List<Function<String, String>> ENCODING_FUNCTIONS =
            List.of(
                    SqlInjectionScanRule::getURLEncode,
                    SqlInjectionScanRule::getHTMLEncode,
                    s -> SqlInjectionScanRule.getHTMLEncode(SqlInjectionScanRule.getURLEncode(s)),
                    StringEscapeUtils::escapeXml10,
                    s -> s // Make sure to test for no encoding as well
                    );

    static Stream<Function<String, String>> reflectionEncodings() {
        return ENCODING_FUNCTIONS.stream();
    }

    @Nested
    class BooleanBasedSqlInjection {

        @Test
        void shouldAlert_ANDTrueMatches_ANDFalseDoesNotMatch() throws Exception {
            // Given
            final String param = "param";
            final String normalValue = "payload";
            final String ANDTrueValue = normalValue + SqlInjectionScanRule.SQL_LOGIC_AND_TRUE[0];
            final String ANDFalseValue = normalValue + SqlInjectionScanRule.SQL_LOGIC_AND_FALSE[0];

            final UrlParamValueHandler handler =
                    UrlParamValueHandler.builder()
                            .targetParam(param)
                            .whenParamValueIs(normalValue)
                            .thenReturnHtml("normal response")
                            .whenParamValueIs(ANDTrueValue)
                            .thenReturnHtml("normal response")
                            .whenParamValueIs(ANDFalseValue)
                            .thenReturnHtml(constructReflectedResponse("different response"))
                            .build();
            nano.addHandler(handler);
            rule.init(getHttpMessage("/?param=" + normalValue), parent);

            // When
            rule.scan();

            // Then
            assertThat(alertsRaised, hasSize(1));
            Alert actual = alertsRaised.get(0);
            assertThat(actual.getParam(), is(equalTo(param)));
            assertThat(actual.getAttack(), is(equalTo(ANDTrueValue)));
        }

        @Test
        void shouldAlert_ANDTrueMatches_ANDFalseMatches_ORTrueDoesNotMatch() throws Exception {
            // Given
            final String param = "param";
            final String normalValue = "payload";
            final String ANDTrueValue = normalValue + SqlInjectionScanRule.SQL_LOGIC_AND_TRUE[0];
            final String ANDFalseValue = normalValue + SqlInjectionScanRule.SQL_LOGIC_AND_FALSE[0];
            final String ORTrueValue = normalValue + SqlInjectionScanRule.SQL_LOGIC_OR_TRUE[0];

            final UrlParamValueHandler handler =
                    UrlParamValueHandler.builder()
                            .targetParam(param)
                            .whenParamValueIs(normalValue)
                            .thenReturnHtml("normal response")
                            .whenParamValueIs(ANDTrueValue)
                            .thenReturnHtml("normal response")
                            .whenParamValueIs(ANDFalseValue)
                            .thenReturnHtml(constructReflectedResponse("normal response"))
                            .whenParamValueIs(ORTrueValue)
                            .thenReturnHtml("different response")
                            .build();
            nano.addHandler(handler);
            rule.init(getHttpMessage("/?param=" + normalValue), parent);

            // When
            rule.scan();

            // Then
            assertThat(alertsRaised, hasSize(1));
            Alert actual = alertsRaised.get(0);
            assertThat(actual.getParam(), is(equalTo(param)));
            assertThat(actual.getAttack(), is(equalTo(ANDTrueValue)));
        }

        @Test
        void shouldNotAlert_ANDTrueMatches_ANDFalseMatches_ORTrueMatches() throws Exception {
            // Given
            final String param = "param";
            final String normalValue = "payload";
            final String ANDTrueValue = normalValue + SqlInjectionScanRule.SQL_LOGIC_AND_TRUE[0];
            final String ANDFalseValue = normalValue + SqlInjectionScanRule.SQL_LOGIC_AND_FALSE[0];
            final String ORTrueValue = normalValue + SqlInjectionScanRule.SQL_LOGIC_OR_TRUE[0];

            final UrlParamValueHandler handler =
                    UrlParamValueHandler.builder()
                            .targetParam(param)
                            .whenParamValueIs(normalValue)
                            .thenReturnHtml("normal response")
                            .whenParamValueIs(ANDTrueValue)
                            .thenReturnHtml("normal response")
                            .whenParamValueIs(ANDFalseValue)
                            .thenReturnHtml("normal response")
                            .whenParamValueIs(ORTrueValue)
                            .thenReturnHtml("normal response")
                            .build();
            nano.addHandler(handler);
            rule.init(getHttpMessage("/?param=" + normalValue), parent);

            // When
            rule.scan();

            // Then
            assertThat(alertsRaised, hasSize(0));
        }

        @Test
        void shouldNotAlert_ANDTrueDoesNotMatch() throws Exception {
            // Given
            final String param = "param";
            final String normalValue = "payload";
            final String ANDTrueValue = normalValue + SqlInjectionScanRule.SQL_LOGIC_AND_TRUE[0];

            final UrlParamValueHandler handler =
                    UrlParamValueHandler.builder()
                            .targetParam(param)
                            .whenParamValueIs(normalValue)
                            .thenReturnHtml("normal response")
                            .whenParamValueIs(ANDTrueValue)
                            .thenReturnHtml("different response")
                            .build();
            nano.addHandler(handler);
            rule.init(getHttpMessage("/?param=" + normalValue), parent);

            // When
            rule.scan();

            // Then
            assertThat(alertsRaised, hasSize(0));
        }

        @ParameterizedTest
        @MethodSource(
                "org.zaproxy.zap.extension.ascanrules.SqlInjectionScanRuleUnitTest#reflectionEncodings")
        void shouldAlert_encodedPayloadReflected(Function<String, String> encodingFunction)
                throws Exception {
            final String param = "param";
            final String normalValue = "<a>%test"; // Includes characters that will be encoded
            final String ANDTrueValue = normalValue + SqlInjectionScanRule.SQL_LOGIC_AND_TRUE[0];
            final String ANDFalseValue = normalValue + SqlInjectionScanRule.SQL_LOGIC_AND_FALSE[0];

            // Set up the positive case where normal and ANDTrue responses match but ANDFalse is
            // different
            final UrlParamValueHandler handler =
                    UrlParamValueHandler.builder()
                            .targetParam(param)
                            .whenParamValueIs(normalValue)
                            .thenReturnHtml(constructReflectedResponse(normalValue))
                            .whenParamValueIs(ANDTrueValue)
                            .thenReturnHtml(
                                    constructReflectedResponse(encodingFunction.apply(normalValue)))
                            .whenParamValueIs(ANDFalseValue)
                            .thenReturnHtml(
                                    constructReflectedResponse(encodingFunction.apply(normalValue))
                                            + "something different")
                            .build();
            nano.addHandler(handler);
            rule.init(getHttpMessage("/?param=" + normalValue), parent);

            // When
            rule.scan();

            // Then
            assertThat(alertsRaised, hasSize(1));
            Alert actual = alertsRaised.get(0);
            assertThat(actual.getParam(), is(equalTo(param)));
            assertThat(actual.getAttack(), is(equalTo(ANDTrueValue)));
        }

        @Test
        void shouldAlert_valueReflectedMultipleTimes_andWithDifferentEncodings() throws Exception {
            // Given
            final String param = "param";
            final String normalValue = "<a>%test"; // Includes characters that will be encoded
            final String ANDTrueValue = normalValue + SqlInjectionScanRule.SQL_LOGIC_AND_TRUE[0];
            final String ANDFalseValue = normalValue + SqlInjectionScanRule.SQL_LOGIC_AND_FALSE[0];

            // Set up the positive case where normal and ANDTrue responses match but ANDFalse is
            // different
            final UrlParamValueHandler handler =
                    UrlParamValueHandler.builder()
                            .targetParam(param)
                            .whenParamValueIs(normalValue)
                            .thenReturnHtml(constructReflectedResponse(normalValue))
                            .whenParamValueIs(ANDTrueValue)
                            .thenReturnHtml(
                                    constructReflectedResponse(escapeXml10(ANDTrueValue), 4))
                            .whenParamValueIs(ANDFalseValue)
                            .thenReturnHtml(
                                    constructReflectedResponse(
                                                    AbstractPlugin.getURLEncode(ANDFalseValue), 2)
                                            + "something different")
                            .build();
            nano.addHandler(handler);
            rule.init(getHttpMessage("/?param=" + normalValue), parent);

            // When
            rule.scan();

            // Then
            assertThat(alertsRaised, hasSize(1));
            Alert actual = alertsRaised.get(0);
            assertThat(actual.getParam(), is(equalTo(param)));
            assertThat(actual.getAttack(), is(equalTo(ANDTrueValue)));
        }

        @Test
        void shouldNotAlert_responseIsSameForAllParameter_originalParameterIsAlwaysInResponse()
                throws Exception {
            // Given
            final String param = "param";
            final String normalValue = "normal";
            final String ANDTrueValue = normalValue + SqlInjectionScanRule.SQL_LOGIC_AND_TRUE[0];
            final String ANDFalseValue = normalValue + SqlInjectionScanRule.SQL_LOGIC_AND_FALSE[0];
            final String ORTrueValue = normalValue + SqlInjectionScanRule.SQL_LOGIC_OR_TRUE[0];

            final UrlParamValueHandler handler =
                    UrlParamValueHandler.builder()
                            .targetParam(param)
                            .whenParamValueIs(normalValue)
                            .thenReturnHtml(constructReflectedResponse(normalValue) + normalValue)
                            .whenParamValueIs(ANDTrueValue)
                            .thenReturnHtml(constructReflectedResponse(ANDTrueValue) + normalValue)
                            .whenParamValueIs(ANDFalseValue)
                            .thenReturnHtml(constructReflectedResponse(ANDFalseValue) + normalValue)
                            .whenParamValueIs(ORTrueValue)
                            .thenReturnHtml(constructReflectedResponse(ORTrueValue) + normalValue)
                            .build();
            nano.addHandler(handler);
            rule.init(getHttpMessage("/?param=" + normalValue), parent);

            // When
            rule.scan();

            // Then
            assertThat(alertsRaised, hasSize(0));
        }

        @Test
        void shouldNotAlert_LIKEAttacks_StrengthMedium() throws Exception {
            // Given
            rule.setAttackStrength(AttackStrength.MEDIUM);
            final String param = "param";
            final String normalValue = "payload";
            final String ANDTrueValue =
                    normalValue
                            + SqlInjectionScanRule.SQL_LOGIC_AND_TRUE[
                                    6]; // 6 is the current index of the first LIKE payload
            final String ANDFalseValue =
                    normalValue
                            + SqlInjectionScanRule.SQL_LOGIC_AND_FALSE[
                                    6]; // 6 is the current index of the first LIKE payload

            // Set up the positive case where normal and ANDTrue responses match but ANDFalse is
            // different
            final UrlParamValueHandler handler =
                    UrlParamValueHandler.builder()
                            .targetParam(param)
                            .whenParamValueIs(normalValue)
                            .thenReturnHtml(constructReflectedResponse(normalValue))
                            .whenParamValueIs(ANDTrueValue)
                            .thenReturnHtml(constructReflectedResponse(ANDTrueValue))
                            .whenParamValueIs(ANDFalseValue)
                            .thenReturnHtml(
                                    constructReflectedResponse("different from normal and ANDTrue"))
                            .build();
            nano.addHandler(handler);
            rule.init(getHttpMessage("/?param=" + normalValue), parent);

            // When
            rule.scan();

            // Then
            assertThat(alertsRaised, hasSize(0));
        }

        @Test
        void shouldAlert_LIKEAttacks_StrengthHigh() throws Exception {
            // Given
            rule.setAttackStrength(AttackStrength.HIGH);
            final String param = "param";
            final String normalValue = "payload";
            final String ANDTrueValue =
                    normalValue
                            + SqlInjectionScanRule.SQL_LOGIC_AND_TRUE[
                                    6]; // 6 is the current index of the first LIKE payload
            final String ANDFalseValue =
                    normalValue
                            + SqlInjectionScanRule.SQL_LOGIC_AND_FALSE[
                                    6]; // 6 is the current index of the first LIKE payload

            // Set up the positive case where normal and ANDTrue responses match but ANDFalse is
            // different
            final UrlParamValueHandler handler =
                    UrlParamValueHandler.builder()
                            .targetParam(param)
                            .whenParamValueIs(normalValue)
                            .thenReturnHtml(constructReflectedResponse(normalValue))
                            .whenParamValueIs(ANDTrueValue)
                            .thenReturnHtml(constructReflectedResponse(ANDTrueValue))
                            .whenParamValueIs(ANDFalseValue)
                            .thenReturnHtml(
                                    constructReflectedResponse("different from normal and ANDTrue"))
                            .build();
            nano.addHandler(handler);
            rule.init(getHttpMessage("/?param=" + normalValue), parent);

            // When
            rule.scan();

            // Then
            assertThat(alertsRaised, hasSize(1));
            Alert actual = alertsRaised.get(0);
            assertThat(actual.getParam(), is(equalTo(param)));
            assertThat(actual.getAttack(), is(equalTo(ANDTrueValue)));
        }

        /** Build a short response that contains the payload reflected in some text */
        private String constructReflectedResponse(String payload) {
            return constructReflectedResponse(payload, 1);
        }

        private String constructReflectedResponse(String payload, int reflectionCount) {
            String response = "foo ";
            for (int i = 0; i < reflectionCount; i++) {
                response += payload;
            }
            return response + " foo ";
        }

        @Test
        void shouldAlertByBodyComparisonIgnoringXmlEscapedPayload() throws Exception {
            // Given
            String param = "topic";
            String normalPayload = "cats";
            String attackPayload = "cats' AND '1'='1' -- ";
            String verificationPayload = "cats' AND '1'='2' -- ";
            UrlParamValueHandler handler =
                    UrlParamValueHandler.builder()
                            .targetParam(param)
                            .whenParamValueIs(normalPayload)
                            .thenReturnHtml(normalPayload + ": A")
                            .whenParamValueIs(attackPayload)
                            .thenReturnHtml(escapeXml10(attackPayload + ": A"))
                            .whenParamValueIs(verificationPayload)
                            .thenReturnHtml(escapeXml10(verificationPayload + ": "))
                            .build();
            nano.addHandler(handler);
            rule.init(getHttpMessage("/?topic=" + normalPayload), parent);

            // When
            rule.scan();

            // Then
            assertThat(alertsRaised, hasSize(1));
            Alert actual = alertsRaised.get(0);
            assertThat(actual.getParam(), is(equalTo(param)));
            assertThat(actual.getAttack(), is(equalTo(attackPayload)));
        }

        @Test
        void shouldNotAlertForChangedStatusCode() throws Exception {
            // Given
            String param = "test";
            String normalPayload = "foo";
            String attackPayload = "foo' AND '1'='1' -- ";
            String verificationPayload = "foo' AND '1'='2' -- ";
            String orTruePayload = "foo' OR '1'='1' -- ";
            Map<String, Supplier<Response>> paramValueToResponseMap = new HashMap<>();
            paramValueToResponseMap.put(
                    normalPayload,
                    () -> newFixedLengthResponse(Status.OK, NanoHTTPD.MIME_HTML, "normal"));
            paramValueToResponseMap.put(
                    attackPayload,
                    () -> newFixedLengthResponse(Status.OK, NanoHTTPD.MIME_HTML, "normal"));
            paramValueToResponseMap.put(
                    verificationPayload,
                    () ->
                            newFixedLengthResponse(
                                    Status.TOO_MANY_REQUESTS,
                                    NanoHTTPD.MIME_HTML,
                                    "too many requests"));
            paramValueToResponseMap.put(
                    orTruePayload,
                    () ->
                            newFixedLengthResponse(
                                    Status.TOO_MANY_REQUESTS,
                                    NanoHTTPD.MIME_HTML,
                                    "too many requests"));
            ControlledStatusCodeHandler handler =
                    new ControlledStatusCodeHandler(param, paramValueToResponseMap);
            nano.addHandler(handler);
            rule.init(getHttpMessage("/?" + param + "=" + normalPayload), parent);

            // When
            rule.scan();

            assertThat(alertsRaised, hasSize(0));
        }
    }

    @Nested
    class ErrorBasedSqlInjection {
        @Test
        void shouldAlert_emptyPrefix() throws Exception {
            // Given
            final String param = "param";
            final String normalValue = "test";
            final String emptyPrefixErrorValue = "" + SqlInjectionScanRule.SQL_CHECK_ERR[0];

            final UrlParamValueHandler handler =
                    UrlParamValueHandler.builder()
                            .targetParam(param)
                            .whenParamValueIs(param)
                            .thenReturnHtml(normalValue)
                            .whenParamValueIs(emptyPrefixErrorValue)
                            .thenReturnHtml("You have an error in your SQL syntax")
                            .build();
            nano.addHandler(handler);
            rule.init(getHttpMessage("/?param=" + normalValue), parent);

            // When
            rule.scan();

            // Then
            assertThat(alertsRaised, hasSize(1));
        }

        @Test
        void shouldAlert_originalParamPrefix() throws Exception {
            // Given
            final String param = "param";
            final String normalValue = "test";
            final String originalParamErrorValue =
                    normalValue + SqlInjectionScanRule.SQL_CHECK_ERR[0];

            final UrlParamValueHandler handler =
                    UrlParamValueHandler.builder()
                            .targetParam(param)
                            .whenParamValueIs(param)
                            .thenReturnHtml(normalValue)
                            .whenParamValueIs(originalParamErrorValue)
                            .thenReturnHtml("You have an error in your SQL syntax")
                            .build();
            nano.addHandler(handler);
            rule.init(getHttpMessage("/?param=" + normalValue), parent);

            // When
            rule.scan();

            // Then
            assertThat(alertsRaised, hasSize(1));
        }

        @Test
        void shouldNotAlert_nonSqlMessage() throws Exception {
            // Given
            final String param = "param";
            final String normalValue = "test";
            final String originalParamErrorValue =
                    normalValue + SqlInjectionScanRule.SQL_CHECK_ERR[0];

            final UrlParamValueHandler handler =
                    UrlParamValueHandler.builder()
                            .targetParam(param)
                            .whenParamValueIs(param)
                            .thenReturnHtml(normalValue)
                            .whenParamValueIs(originalParamErrorValue)
                            .thenReturnHtml("Not a SQL error message")
                            .build();
            nano.addHandler(handler);
            rule.init(getHttpMessage("/?param=" + normalValue), parent);

            // When
            rule.scan();

            // Then
            assertThat(alertsRaised, hasSize(0));
        }

        @Test
        void shouldAlert_genericRDBMSError() throws Exception {
            // Given
            rule.setAlertThreshold(
                    AlertThreshold.LOW); // Generic are currently only checked at the low threshold
            final String param = "param";
            final String normalValue = "test";
            final String originalParamErrorValue =
                    normalValue + SqlInjectionScanRule.SQL_CHECK_ERR[0];

            final UrlParamValueHandler handler =
                    UrlParamValueHandler.builder()
                            .targetParam(param)
                            .whenParamValueIs(param)
                            .thenReturnHtml(normalValue)
                            .whenParamValueIs(originalParamErrorValue)
                            .thenReturnHtml("java.sql.SQLException")
                            .build();
            nano.addHandler(handler);
            rule.init(getHttpMessage("/?param=" + normalValue), parent);

            // When
            rule.scan();

            // Then
            assertThat(alertsRaised, hasSize(1));
        }
    }

    @Nested
    class UnionBasedSqlInjection {
        @Test
        void shouldAlert_RDBMSErrorMessage() throws Exception {
            // Given
            final String param = "param";
            final String normalValue = "test";
            final String unionValueString =
                    normalValue + SqlInjectionScanRule.SQL_UNION_APPENDAGES[0];

            final UrlParamValueHandler handler =
                    UrlParamValueHandler.builder()
                            .targetParam(param)
                            .whenParamValueIs(param)
                            .thenReturnHtml(normalValue)
                            .whenParamValueIs(unionValueString)
                            .thenReturnHtml("You have an error in your SQL syntax")
                            .build();
            nano.addHandler(handler);
            rule.init(getHttpMessage("/?param=" + normalValue), parent);

            // When
            rule.scan();

            // Then
            assertThat(alertsRaised, hasSize(1));
        }

        @Test
        void shouldNotAlert_nonErrorMessageResponse() throws Exception {
            // Given
            final String param = "param";
            final String normalValue = "test";
            final String unionValueString =
                    normalValue + SqlInjectionScanRule.SQL_UNION_APPENDAGES[0];

            final UrlParamValueHandler handler =
                    UrlParamValueHandler.builder()
                            .targetParam(param)
                            .whenParamValueIs(param)
                            .thenReturnHtml(normalValue)
                            .whenParamValueIs(unionValueString)
                            .thenReturnHtml("This is not a sql error message")
                            .build();
            nano.addHandler(handler);
            rule.init(getHttpMessage("/?param=" + normalValue), parent);

            // When
            rule.scan();

            // Then
            assertThat(alertsRaised, hasSize(0));
        }

        @Test
        void shouldNotRun_strengthLOW() throws Exception {
            // Given
            rule.setAttackStrength(AttackStrength.LOW);
            final String param = "param";
            final String normalValue = "test";
            final String unionValueString =
                    normalValue + SqlInjectionScanRule.SQL_UNION_APPENDAGES[0];

            final UrlParamValueHandler handler =
                    UrlParamValueHandler.builder()
                            .targetParam(param)
                            .whenParamValueIs(param)
                            .thenReturnHtml(normalValue)
                            .whenParamValueIs(unionValueString)
                            .thenReturnHtml("You have an error in your SQL syntax")
                            .build();
            nano.addHandler(handler);
            rule.init(getHttpMessage("/?param=" + normalValue), parent);

            // When
            rule.scan();

            // Then
            assertThat(alertsRaised, hasSize(0));
        }
    }

    private static class ExpressionBasedHandler extends NanoServerHandler {

        public enum Expression {
            SUM("1", "3-2", "4-2"),
            MULT("1", "2/2", "4/2");

            private final String value;
            private final String baseExpression;
            private final String confirmationExpression;

            Expression(String value, String expression, String confirmationExpression) {
                this.value = value;
                this.baseExpression = expression;
                this.confirmationExpression = confirmationExpression;
            }
        }

        private final String param;
        private final Expression expression;
        private final boolean confirmationFails;
        private String contentAddition = "";

        public ExpressionBasedHandler(String path, String param, Expression expression) {
            this(path, param, expression, false);
        }

        public ExpressionBasedHandler(
                String path, String param, Expression expression, boolean confirmationFails) {
            super(path);

            this.param = param;
            this.expression = expression;
            this.confirmationFails = confirmationFails;
        }

        public ExpressionBasedHandler(
                String path,
                String param,
                Expression expression,
                boolean confirmationFails,
                String contentAddition) {
            this(path, param, expression, confirmationFails);
            this.contentAddition = contentAddition;
        }

        @Override
        protected Response serve(IHTTPSession session) {
            String value = getFirstParamValue(session, param);
            if (isValidValue(value)) {
                return newFixedLengthResponse(
                        Response.Status.OK, NanoHTTPD.MIME_HTML, getContent(value));
            }
            return newFixedLengthResponse(
                    Response.Status.OK, NanoHTTPD.MIME_HTML, "This is different content");
        }

        private boolean isValidValue(String value) {
            if (confirmationFails && expression.confirmationExpression.equals(value)) {
                return true;
            }
            return expression.value.equals(value) || expression.baseExpression.equals(value);
        }

        protected String getContent(String value) {
            return "Some Content " + contentAddition;
        }
    }

    /**
     * A test server that can respond with different status codes depending on the request payload
     */
    private static class ControlledStatusCodeHandler extends NanoServerHandler {
        private final String targetParam;
        private final Map<String, Supplier<Response>>
                paramValueToResponseMap; // Supplier function because the test may send the same
        // payload multiple times
        private final Supplier<Response> fallbackResponse =
                () -> newFixedLengthResponse(Status.OK, NanoHTTPD.MIME_HTML, "");

        public ControlledStatusCodeHandler(
                String targetParam, Map<String, Supplier<Response>> paramValueToResponseMap) {
            super("/");
            this.targetParam = targetParam;
            this.paramValueToResponseMap = paramValueToResponseMap;
        }

        @Override
        protected Response serve(IHTTPSession session) {
            String actualParamValue = getFirstParamValue(session, targetParam);

            @SuppressWarnings("unchecked")
            final Supplier<Response> responseFn =
                    (Supplier<Response>)
                            MapUtils.getObject(
                                    paramValueToResponseMap, actualParamValue, fallbackResponse);
            final Response response = responseFn.get();
            return response;
        }
    }
}
