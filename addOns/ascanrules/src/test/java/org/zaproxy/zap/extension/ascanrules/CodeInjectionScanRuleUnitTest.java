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
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

import fi.iki.elonen.NanoHTTPD;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;
import org.zaproxy.zap.testutils.NanoServerHandler;

/** Unit test for {@link CodeInjectionScanRule}. */
class CodeInjectionScanRuleUnitTest extends ActiveScannerTest<CodeInjectionScanRule> {

    @Override
    protected int getRecommendMaxNumberMessagesPerParam(AttackStrength strength) {
        int recommendMax = super.getRecommendMaxNumberMessagesPerParam(strength);
        switch (strength) {
            case LOW:
                return recommendMax + 2;
            case MEDIUM:
            default:
                return recommendMax;
            case HIGH:
                return recommendMax;
            case INSANE:
                return recommendMax;
        }
    }

    @Override
    protected CodeInjectionScanRule createScanner() {
        return new CodeInjectionScanRule();
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        int cwe = rule.getCweId();
        int wasc = rule.getWascId();
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(cwe, is(equalTo(94)));
        assertThat(wasc, is(equalTo(20)));
        assertThat(tags.size(), is(equalTo(3)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A03_INJECTION.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A01_INJECTION.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.WSTG_V42_INPV_11_CODE_INJ.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A03_INJECTION.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A03_INJECTION.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A01_INJECTION.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A01_INJECTION.getValue())));
        assertThat(
                tags.get(CommonAlertTag.WSTG_V42_INPV_11_CODE_INJ.getTag()),
                is(equalTo(CommonAlertTag.WSTG_V42_INPV_11_CODE_INJ.getValue())));
    }

    @Test
    void shouldTargetAspTech() {
        // Given
        TechSet techSet = techSet(Tech.ASP);
        // When
        boolean targets = rule.targets(techSet);
        // Then
        assertThat(targets, is(equalTo(true)));
    }

    @Test
    void shouldTargetPhpTech() {
        // Given
        TechSet techSet = techSet(Tech.PHP);
        // When
        boolean targets = rule.targets(techSet);
        // Then
        assertThat(targets, is(equalTo(true)));
    }

    @Test
    void shouldNotTargetNonAspPhpTechs() {
        // Given
        TechSet techSet = techSetWithout(Tech.ASP, Tech.PHP);
        // When
        boolean targets = rule.targets(techSet);
        // Then
        assertThat(targets, is(equalTo(false)));
    }

    @Test
    void shouldFindPhpInjection() throws Exception {
        // Given
        String test = "/shouldFindPhpInjection.php";
        String PHP_ENCODED_TOKEN =
                "chr(122).chr(97).chr(112).chr(95).chr(116).chr(111).chr(107).chr(101).chr(110)";
        String PHP_PAYLOAD = "print(" + PHP_ENCODED_TOKEN + ")";
        String PHP_CONTROL_TOKEN = "zap_token";

        this.nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected NanoHTTPD.Response serve(NanoHTTPD.IHTTPSession session) {
                        String years = getFirstParamValue(session, "years");
                        if (years.contains(PHP_PAYLOAD)) {
                            return newFixedLengthResponse(
                                    "<html><body>" + PHP_CONTROL_TOKEN + "</body></html>");
                        }
                        return newFixedLengthResponse("<html><body></body></html>");
                    }
                });
        // When
        HttpMessage msg = this.getHttpMessage(test + "?years=1");
        this.rule.init(msg, this.parent);
        this.rule.scan();
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getParam(), equalTo("years"));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo(PHP_CONTROL_TOKEN));
    }

    @Test
    void shouldFindAspInjection() throws Exception {
        // Given
        String test = "/shouldFindAspInjection";
        List<String> evaluationResults = new ArrayList<>();

        this.nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected NanoHTTPD.Response serve(NanoHTTPD.IHTTPSession session) {
                        String years = getFirstParamValue(session, "years");
                        String responseWriteRgx =
                                "response\\.write\\(([0-9]{1,3}(?:,[0-9]{3})?)\\*([0-9]{1,3}(?:,[0-9]{3})?)\\)";

                        Pattern pattern = Pattern.compile(responseWriteRgx);
                        Matcher matcher = pattern.matcher(years);

                        if (matcher.find()) {
                            int num1 = Integer.parseInt(matcher.group(1).replace(",", ""));
                            int num2 = Integer.parseInt(matcher.group(2).replace(",", ""));
                            String resultEval = String.valueOf((long) num1 * num2);
                            evaluationResults.add(resultEval);
                            return newFixedLengthResponse(
                                    "<html><body>" + resultEval + "</body></html>");
                        }
                        return newFixedLengthResponse("<html><body>years</body></html>");
                    }
                });
        // When
        HttpMessage msg = this.getHttpMessage(test + "?years=1");
        this.rule.init(msg, this.parent);
        this.rule.scan();
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getParam(), equalTo("years"));
        boolean evidenceOnEvaluationResults = false;
        for (String result : evaluationResults) {
            if (alertsRaised.get(0).getEvidence().contains(result))
                evidenceOnEvaluationResults = true;
        }
        assert (evidenceOnEvaluationResults);
    }
}
