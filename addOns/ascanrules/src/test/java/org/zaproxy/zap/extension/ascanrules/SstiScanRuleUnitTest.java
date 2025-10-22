/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.lessThanOrEqualTo;

import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.zap.testutils.NanoServerHandler;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

class SstiScanRuleUnitTest extends ActiveScannerTest<SstiScanRule> {

    private static final int SIZESMALLERTHATPOLYGLOT = 12;

    @Override
    protected SstiScanRule createScanner() {
        return new SstiScanRule();
    }

    @Override
    protected int getRecommendMaxNumberMessagesPerParam(Plugin.AttackStrength strength) {
        int recommendMax = super.getRecommendMaxNumberMessagesPerParam(strength);
        switch (strength) {
            case LOW:
                return recommendMax;
            case MEDIUM:
                return recommendMax + 3;
            case HIGH:
                return recommendMax;
            case INSANE:
                return recommendMax;
            default:
                return recommendMax;
        }
    }

    @ParameterizedTest
    @EnumSource(
            value = AttackStrength.class,
            names = {"LOW", "MEDIUM", "HIGH", "INSANE"})
    void shouldNotReportSstiWithoutRendering(AttackStrength strength)
            throws NullPointerException, IOException {
        // Given
        String test = "/shouldReportSstiInRenderedOutput/";
        nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String name = getFirstParamValue(session, "name");
                        String response;
                        if (name != null) {
                            response =
                                    getHtml(
                                            "sstiscanrule/Rendered.html",
                                            new String[][] {{"name", name}});
                        } else {
                            response = getHtml("sstiscanrule/NoInput.html");
                        }
                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = getHttpMessage(test + "?name=test");
        rule.setAttackStrength(strength);
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldNotDoMathsExecutionTestIfInThresholdLowAndNoSuspectBehavior()
            throws HttpMalformedHeaderException {
        // Given
        String test = "/shouldNotDoMathsExecutionTestIfInThresholdLowAndNoSuspectBehavior/";
        nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String name = getFirstParamValue(session, "name");
                        String response;
                        if (name != null) {
                            response =
                                    getHtml(
                                            "sstiscanrule/Rendered.html",
                                            new String[][] {{"name", name}});
                        } else {
                            response = getHtml("sstiscanrule/NoInput.html");
                        }
                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = getHttpMessage(test + "?name=test");
        rule.setAlertThreshold(AlertThreshold.LOW);
        rule.setAttackStrength(Plugin.AttackStrength.LOW);
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(lessThanOrEqualTo(5)));
        assertThat(httpMessagesSent, hasSize(greaterThan(0)));
    }

    @Test
    void shouldNotConsiderInputSizeErrorsAsStrangeBehavior() throws HttpMalformedHeaderException {
        // Given
        String test = "/shouldNotConsiderInputSizeErrorsAsStrangeBehavior/";
        nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String name = getFirstParamValue(session, "name");
                        String response;
                        if (name != null) {
                            if (name.length() > SIZESMALLERTHATPOLYGLOT) {
                                name = "Error: the maximum size is " + SIZESMALLERTHATPOLYGLOT;
                            }
                            response =
                                    getHtml(
                                            "sstiscanrule/Rendered.html",
                                            new String[][] {{"name", name}});
                        } else {
                            response = getHtml("sstiscanrule/NoInput.html");
                        }
                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = getHttpMessage(test + "?name=test");
        rule.setAlertThreshold(AlertThreshold.LOW);
        rule.setAttackStrength(Plugin.AttackStrength.LOW);
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(lessThanOrEqualTo(5)));
        assertThat(httpMessagesSent, hasSize(greaterThan(0)));
    }

    private static Stream<Arguments> shouldReportSetSource() {
        return Stream.of(
                Arguments.of("{", "}", Plugin.AttackStrength.LOW),
                Arguments.of("${", "}", Plugin.AttackStrength.LOW),
                Arguments.of("#{", "}", Plugin.AttackStrength.LOW),
                Arguments.of("{#", "}", Plugin.AttackStrength.LOW),
                Arguments.of("{@", "}", Plugin.AttackStrength.LOW),
                Arguments.of("{{", "}}", Plugin.AttackStrength.LOW),
                Arguments.of("{{=", "}}", Plugin.AttackStrength.LOW),
                Arguments.of("<%=", "%>", Plugin.AttackStrength.LOW),
                Arguments.of("#set($x=", ")${x}", Plugin.AttackStrength.MEDIUM),
                Arguments.of("<p th:text=\"${", "}\"></p>", Plugin.AttackStrength.MEDIUM));
    }

    @ParameterizedTest
    @MethodSource("shouldReportSetSource")
    void shouldReportSsti(String startTag, String endTag, Plugin.AttackStrength level)
            throws NullPointerException, IOException {
        String test = "/shouldReportSsti/";
        // Given
        nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String name = getFirstParamValue(session, "name");
                        String response;
                        if (name != null) {
                            try {
                                name = templateRenderMock(startTag, endTag, name);
                                response =
                                        getHtml(
                                                "sstiscanrule/Rendered.html",
                                                new String[][] {{"name", name}});
                            } catch (IllegalArgumentException e) {
                                response = getHtml("sstiscanrule/ErrorPage.html");
                            }
                        } else {
                            response = getHtml("sstiscanrule/NoInput.html");
                        }
                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = getHttpMessage(test + "?name=test");
        rule.setConfig(new ZapXmlConfiguration());
        rule.setAttackStrength(level);
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_HIGH));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_HIGH));
    }

    @Test
    void shouldReportGoBasedSsti() throws NullPointerException, IOException {
        String test = "/shouldReportGoBasedSsti/";
        // Given
        nano.addHandler(createGoHandler(test, true));
        HttpMessage msg = getHttpMessage(test + "?name=test");
        rule.setConfig(new ZapXmlConfiguration());
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_HIGH));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_HIGH));
    }

    @Test
    void shouldNotReportGoBasedSstiWhenDirectiveEchoed() throws NullPointerException, IOException {
        String test = "/shouldNotReportGoBasedSstiWhenDirectiveEchoed/";
        // Given
        nano.addHandler(createGoHandler(test, false));
        HttpMessage msg = getHttpMessage(test + "?name=test");
        rule.setConfig(new ZapXmlConfiguration());
        rule.setAttackStrength(Plugin.AttackStrength.MEDIUM);
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        int cwe = rule.getCweId();
        int wasc = rule.getWascId();
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(cwe, is(equalTo(1336)));
        assertThat(wasc, is(equalTo(20)));
        assertThat(tags.size(), is(equalTo(12)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A03_INJECTION.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A01_INJECTION.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.WSTG_V42_INPV_18_SSTI.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.API.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.DEV_CICD.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.DEV_STD.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.DEV_FULL.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.QA_CICD.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.QA_STD.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.QA_FULL.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.SEQUENCE.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.PENTEST.getTag()), is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A03_INJECTION.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A03_INJECTION.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A01_INJECTION.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A01_INJECTION.getValue())));
        assertThat(
                tags.get(CommonAlertTag.WSTG_V42_INPV_18_SSTI.getTag()),
                is(equalTo(CommonAlertTag.WSTG_V42_INPV_18_SSTI.getValue())));
    }

    @Test
    void shouldHaveExpectedExampleAlert() {
        // Given / When
        List<Alert> alerts = rule.getExampleAlerts();
        Alert example = alerts.get(0);
        // Then
        assertThat(alerts.size(), is(equalTo(1)));
        assertThat(example.getConfidence(), is(equalTo(Alert.CONFIDENCE_HIGH)));
        assertThat(example.getParam(), is(equalTo("name")));
        assertThat(example.getAttack(), is(equalTo("zj#set($x=2614*1450)${x}zj")));
    }

    private static String templateRenderMock(String startTag, String endTag, String input)
            throws IllegalArgumentException {
        if (!input.contains(startTag)) {
            return input;
        }

        String[] prefixAndRest = input.split(Pattern.quote(startTag), 2);
        String prefix = prefixAndRest[0];

        if (prefixAndRest.length < 2 || !prefixAndRest[1].contains(endTag)) {
            return input;
        }

        String[] expressionAndSuffix = prefixAndRest[1].split(Pattern.quote(endTag), 2);
        String expression = expressionAndSuffix[0];
        String suffix = expressionAndSuffix[1];
        String expressionResult = getSimpleArithmeticResult(expression);
        return prefix + expressionResult + suffix;
    }

    private static String getSimpleArithmeticResult(String expression)
            throws IllegalArgumentException {
        if (expression.contains("+")) {
            String[] numbers = expression.split(Pattern.quote("+"), 2);
            if (numbers.length == 1 && expression.endsWith("+")) {
                throw new IllegalArgumentException("invalid template code");
            } else if (numbers.length != 2) {
                throw new IllegalArgumentException("invalid template code");
            }
            return Integer.toString((Integer.parseInt(numbers[0]) + Integer.parseInt(numbers[1])));
        } else if (expression.contains("*")) {
            String[] numbers = expression.split(Pattern.quote("*"), 2);
            if (numbers.length == 1 && expression.endsWith("*")) {
                throw new IllegalArgumentException("invalid template code");
            } else if (numbers.length != 2) {
                throw new IllegalArgumentException("invalid template code");
            }
            return Integer.toString((Integer.parseInt(numbers[0]) * Integer.parseInt(numbers[1])));
        } else if (StringUtils.isNumeric(expression)) {
            return expression;
        } else {
            throw new IllegalArgumentException("invalid template code");
        }
    }

    private NanoServerHandler createGoHandler(String path, boolean stripPrint) {
        return new NanoServerHandler(path) {
            @Override
            protected Response serve(IHTTPSession session) {
                String name = getFirstParamValue(session, "name");
                String response;
                if (name != null) {
                    if (!name.contains("print")) {
                        return newFixedLengthResponse(getHtml("sstiscanrule/NoInput.html"));
                    }
                    try {
                        if (name.contains("print")) {
                            name = name.replaceAll("[^A-Za-z0-9]+", "");
                            name = stripPrint ? name.replace("print", "") : name;
                        }
                        name = templateRenderMock("{", "}", name);
                        response =
                                getHtml(
                                        "sstiscanrule/Rendered.html",
                                        new String[][] {{"name", name}});
                    } catch (IllegalArgumentException e) {
                        response = getHtml("sstiscanrule/ErrorPage.html");
                    }
                } else {
                    response = getHtml("sstiscanrule/NoInput.html");
                }
                return newFixedLengthResponse(response);
            }
        };
    }
}
