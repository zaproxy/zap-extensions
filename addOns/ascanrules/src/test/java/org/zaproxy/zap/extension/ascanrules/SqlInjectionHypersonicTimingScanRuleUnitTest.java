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

import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;
import org.zaproxy.zap.testutils.NanoServerHandler;

/** Unit test for {@link SqlInjectionHypersonicTimingScanRule}. */
class SqlInjectionHypersonicTimingScanRuleUnitTest
        extends ActiveScannerTest<SqlInjectionHypersonicTimingScanRule> {

    @Override
    protected SqlInjectionHypersonicTimingScanRule createScanner() {
        return new SqlInjectionHypersonicTimingScanRule();
    }

    @Test
    void shouldTargetHypersonicSqlTech() {
        // Given
        TechSet techSet = techSet(Tech.HypersonicSQL);
        // When
        boolean targets = rule.targets(techSet);
        // Then
        assertThat(targets, is(equalTo(true)));
    }

    @Test
    void shouldNotTargetNonHypersonicSqlTechs() {
        // Given
        TechSet techSet = techSetWithout(Tech.HypersonicSQL);
        // When
        boolean targets = rule.targets(techSet);
        // Then
        assertThat(targets, is(equalTo(false)));
    }

    @Test
    void shouldAlertIfSleepTimesGetLonger() throws Exception {
        String test = "/shouldReportSqlTimingIssue/";
        // Match one of the middle payloads, for proper evidence check.
        Pattern sleepPattern =
                Pattern.compile("\\); select \"java.lang.Thread.sleep\"\\((\\d+)\\)");

        this.nano.addHandler(
                new NanoServerHandler(test) {

                    @Override
                    protected Response serve(IHTTPSession session) {
                        String name = getFirstParamValue(session, "name");
                        String response = "<html><body></body></html>";
                        if (name == null) {
                            return newFixedLengthResponse(response);
                        }
                        Matcher match = sleepPattern.matcher(name);
                        if (!match.find()) {
                            return newFixedLengthResponse(name);
                        }
                        try {
                            int sleepInput = Integer.parseInt(match.group(1));
                            Thread.sleep(sleepInput);
                        } catch (InterruptedException e) {
                            // Ignore
                        }
                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = this.getHttpMessage(test + "?name=test");

        this.rule.init(msg, this.parent);
        this.rule.setTimeSleepSeconds(2);

        this.rule.scan();

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getParam(), equalTo("name"));
        assertThat(
                alertsRaised.get(0).getAttack(),
                equalTo(
                        "); select \"java.lang.Thread.sleep\"(2000) from INFORMATION_SCHEMA.SYSTEM_COLUMNS where TABLE_NAME = 'SYSTEM_COLUMNS' and COLUMN_NAME = 'TABLE_NAME' -- "));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_HIGH));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
    }

    @Test
    void shouldNotAlertIfAllTimesGetLonger() throws Exception {
        String test = "/shouldNotReportGeneralTimingIssue/";

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
        this.rule.setTimeSleepSeconds(2);

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
        assertThat(tags.size(), is(equalTo(11)));
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
        assertThat(tags.containsKey(PolicyTag.DEV_FULL.getTag()), is(equalTo(true)));
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
                tags.get(CommonAlertTag.WSTG_V42_INPV_05_SQLI.getTag()),
                is(equalTo(CommonAlertTag.WSTG_V42_INPV_05_SQLI.getValue())));
    }
}
