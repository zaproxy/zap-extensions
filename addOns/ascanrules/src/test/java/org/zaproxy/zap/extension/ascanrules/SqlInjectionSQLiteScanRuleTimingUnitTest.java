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
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.startsWith;

import org.junit.jupiter.api.Test;

/** Unit test for {@link SqlInjectionSqLiteScanRule}. */
class SqlInjectionSQLiteScanRuleTimingUnitTest
        extends ActiveScannerTest<SqlInjectionSqLiteTimingScanRule> {

    @Override
    protected SqlInjectionSqLiteTimingScanRule createScanner() {
        return new SqlInjectionSqLiteTimingScanRule();
    }

    // Give a bit more leeway
    @Override
    protected int getRecommendMaxNumberMessagesPerParam(
            org.parosproxy.paros.core.scanner.Plugin.AttackStrength strength) {
        switch (strength) {
            case LOW:
                return NUMBER_MSGS_ATTACK_STRENGTH_LOW;
            case MEDIUM:
            default:
                return NUMBER_MSGS_ATTACK_STRENGTH_MEDIUM + 2;
            case HIGH:
                return NUMBER_MSGS_ATTACK_STRENGTH_HIGH + 10;
            case INSANE:
                return NUMBER_MSGS_ATTACK_STRENGTH_INSANE + 22;
        }
    }

    @Test
    void shouldTargetSqLiteSQLTech() throws Exception {
        // Given
        org.zaproxy.zap.model.TechSet techSet = techSet(org.zaproxy.zap.model.Tech.SQLite);
        // When
        boolean targets = rule.targets(techSet);
        // Then
        assertThat(targets, is(equalTo(true)));
    }

    @Test
    void shouldNotTargetNonSqLiteSQLTechs() throws Exception {
        // Given
        org.zaproxy.zap.model.TechSet techSet = techSetWithout(org.zaproxy.zap.model.Tech.SQLite);
        // When
        boolean targets = rule.targets(techSet);
        // Then
        assertThat(targets, is(equalTo(false)));
    }

    @Test
    void shouldAlertIfSqlErrorReturned() throws Exception {
        String test = "/shouldReportSqlErrorMessage/";

        this.nano.addHandler(
                new org.zaproxy.zap.testutils.NanoServerHandler(test) {
                    @Override
                    protected fi.iki.elonen.NanoHTTPD.Response serve(
                            fi.iki.elonen.NanoHTTPD.IHTTPSession session) {
                        String name = getFirstParamValue(session, "name");
                        String response = "<html><body></body></html>";
                        if (name != null && name.contains(" randomblob(")) {
                            response =
                                    "<html><body>SQL error: no such function: randomblob</body></html>";
                        }
                        return newFixedLengthResponse(response);
                    }
                });

        org.parosproxy.paros.network.HttpMessage msg = this.getHttpMessage(test + "?name=test");

        this.rule.init(msg, this.parent);

        this.rule.scan();

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo("no such function: randomblob"));
        assertThat(alertsRaised.get(0).getParam(), equalTo("name"));
        assertThat(
                alertsRaised.get(0).getAttack(),
                equalTo("case randomblob(100000) when not null then 1 else 1 end "));
        assertThat(
                alertsRaised.get(0).getRisk(),
                equalTo(org.parosproxy.paros.core.scanner.Alert.RISK_HIGH));
        assertThat(
                alertsRaised.get(0).getConfidence(),
                equalTo(org.parosproxy.paros.core.scanner.Alert.CONFIDENCE_MEDIUM));
    }

    @Test
    void shouldAlertIfRandomBlobTimesGetLonger() throws Exception {
        String test = "/shouldReportSqlTimingIssue/";

        this.nano.addHandler(
                new org.zaproxy.zap.testutils.NanoServerHandler(test) {
                    private int time = 100;

                    @Override
                    protected fi.iki.elonen.NanoHTTPD.Response serve(
                            fi.iki.elonen.NanoHTTPD.IHTTPSession session) {
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

        org.parosproxy.paros.network.HttpMessage msg = this.getHttpMessage(test + "?name=test");

        this.rule.init(msg, this.parent);

        this.rule.scan();

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(
                alertsRaised.get(0).getEvidence(),
                startsWith("The query time is controllable using parameter value"));
        assertThat(alertsRaised.get(0).getParam(), equalTo("name"));
        assertThat(alertsRaised.get(0).getAttack(), startsWith("case randomblob(100"));
        assertThat(
                alertsRaised.get(0).getRisk(),
                equalTo(org.parosproxy.paros.core.scanner.Alert.RISK_HIGH));
        assertThat(
                alertsRaised.get(0).getConfidence(),
                equalTo(org.parosproxy.paros.core.scanner.Alert.CONFIDENCE_MEDIUM));
    }

    @Test
    void shouldNotAlertIfAllTimesGetLonger() throws Exception {
        String test = "/shouldReportSqlTimingIssue/";

        this.nano.addHandler(
                new org.zaproxy.zap.testutils.NanoServerHandler(test) {
                    private int time = 100;

                    @Override
                    protected fi.iki.elonen.NanoHTTPD.Response serve(
                            fi.iki.elonen.NanoHTTPD.IHTTPSession session) {
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

        org.parosproxy.paros.network.HttpMessage msg = this.getHttpMessage(test + "?name=test");

        this.rule.init(msg, this.parent);

        this.rule.scan();

        assertThat(alertsRaised.size(), equalTo(0));
    }
}
