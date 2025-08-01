/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
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
import static org.hamcrest.Matchers.startsWith;

import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;
import org.zaproxy.zap.testutils.NanoServerHandler;

/** Unit test for {@link SqlInjectionSqLiteTimingScanRule}. */
class SqlInjectionSqLiteTimingScanRuleUnitTest
        extends ActiveScannerTest<SqlInjectionSqLiteTimingScanRule> {

    @Override
    protected SqlInjectionSqLiteTimingScanRule createScanner() {
        return new SqlInjectionSqLiteTimingScanRule();
    }

    // Give a bit more leeway
    @Override
    protected int getRecommendMaxNumberMessagesPerParam(Plugin.AttackStrength strength) {
        switch (strength) {
            case LOW:
                return NUMBER_MSGS_ATTACK_STRENGTH_LOW;
            case MEDIUM:
            default:
                return NUMBER_MSGS_ATTACK_STRENGTH_MEDIUM;
            case HIGH:
                return NUMBER_MSGS_ATTACK_STRENGTH_HIGH + 5;
            case INSANE:
                return NUMBER_MSGS_ATTACK_STRENGTH_INSANE + 25;
        }
    }

    @Test
    void shouldTargetSqLiteSqlTech() {
        // Given
        TechSet techSet = techSet(Tech.SQLite);
        // When
        boolean targets = rule.targets(techSet);
        // Then
        assertThat(targets, is(equalTo(true)));
    }

    @Test
    void shouldNotTargetNonSqLiteSqlTechs() {
        // Given
        TechSet techSet = techSetWithout(Tech.SQLite);
        // When
        boolean targets = rule.targets(techSet);
        // Then
        assertThat(targets, is(equalTo(false)));
    }

    @Test
    void shouldAlertIfSqlErrorReturned() throws Exception {
        String test = "/shouldReportSqlErrorMessage/";

        this.nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String name = getFirstParamValue(session, "name");
                        String response = "<html><body></body></html>";
                        if (name != null && name.contains(" randomblob(")) {
                            response =
                                    "<html><body>SQL error: no such function: randomblob</body></html>";
                        }
                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = this.getHttpMessage(test + "?name=test");

        this.rule.init(msg, this.parent);

        this.rule.scan();

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo("no such function: randomblob"));
        assertThat(alertsRaised.get(0).getParam(), equalTo("name"));
        assertThat(
                alertsRaised.get(0).getAttack(),
                equalTo("case randomblob(100000) when not null then 1 else 1 end "));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_HIGH));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
    }

    @Test
    void shouldAlertIfRandomBlobTimesGetLonger() throws Exception {
        String test = "/shouldReportSqlTimingIssue/";

        this.nano.addHandler(
                new NanoServerHandler(test) {
                    private int time = 100;

                    @Override
                    protected Response serve(IHTTPSession session) {
                        String name = getFirstParamValue(session, "name");
                        String response = "<html><body></body></html>";
                        if (name != null && name.contains(" randomblob(")) {
                            try {
                                Thread.sleep(time);
                            } catch (InterruptedException e) {
                                // Ignore
                            }
                            time += 100;
                        }
                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = this.getHttpMessage(test + "?name=test");

        this.rule.init(msg, this.parent);
        this.rule.setExpectedDelayInMs(90);

        this.rule.scan();

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getParam(), equalTo("name"));
        assertThat(alertsRaised.get(0).getAttack(), startsWith("case randomblob(100"));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_HIGH));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
    }

    @Test
    void shouldNotAlertIfAllTimesGetLonger() throws Exception {
        String test = "/shouldReportSqlTimingIssue/";

        this.nano.addHandler(
                new NanoServerHandler(test) {
                    private int time = 100;

                    @Override
                    protected Response serve(IHTTPSession session) {
                        String response = "<html><body></body></html>";
                        try {
                            Thread.sleep(time);
                        } catch (InterruptedException e) {
                            // Ignore
                        }
                        time += 100;
                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = this.getHttpMessage(test + "?name=test");

        this.rule.init(msg, this.parent);
        this.rule.setExpectedDelayInMs(90);

        this.rule.scan();

        assertThat(alertsRaised.size(), equalTo(0));
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
        assertThat(tags.size(), is(equalTo(8)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A03_INJECTION.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A01_INJECTION.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.WSTG_V42_INPV_05_SQLI.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(CommonAlertTag.HIPAA.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(CommonAlertTag.PCI_DSS.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(CommonAlertTag.TEST_TIMING.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.QA_FULL.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.PENTEST.getTag()), is(equalTo(true)));
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
}
