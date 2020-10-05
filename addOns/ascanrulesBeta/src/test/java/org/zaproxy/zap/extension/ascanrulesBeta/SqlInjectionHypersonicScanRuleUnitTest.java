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
package org.zaproxy.zap.extension.ascanrulesBeta;

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;
import org.zaproxy.zap.testutils.NanoServerHandler;

/** Unit test for {@link SqlInjectionHypersonicScanRule}. */
public class SqlInjectionHypersonicScanRuleUnitTest
        extends ActiveScannerTest<SqlInjectionHypersonicScanRule> {

    @Override
    protected SqlInjectionHypersonicScanRule createScanner() {
        return new SqlInjectionHypersonicScanRule();
    }

    @Test
    public void shouldTargetHypersonicSQLTech() throws Exception {
        // Given
        TechSet techSet = techSet(Tech.HypersonicSQL);
        // When
        boolean targets = rule.targets(techSet);
        // Then
        assertThat(targets, is(equalTo(true)));
    }

    @Test
    public void shouldNotTargetNonHypersonicSQLTechs() throws Exception {
        // Given
        TechSet techSet = techSetWithout(Tech.HypersonicSQL);
        // When
        boolean targets = rule.targets(techSet);
        // Then
        assertThat(targets, is(equalTo(false)));
    }

    @Test
    public void shouldAlertIfSleepTimesGetLonger() throws Exception {
        String test = "/shouldReportSqlTimingIssue/";

        this.nano.addHandler(
                new NanoServerHandler(test) {
                    private int time = 100;

                    @Override
                    protected Response serve(IHTTPSession session) {
                        String name = getFirstParamValue(session, "name");
                        String response = "<html><body></body></html>";
                        if (name != null && name.contains("Thread.sleep")) {
                            try {
                                Thread.sleep(time);
                            } catch (InterruptedException e) {
                                // Ignore
                            }
                            time += 300;
                        }
                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = this.getHttpMessage(test + "?name=test");

        this.rule.init(msg, this.parent);
        this.rule.setSleepInMs(300);

        this.rule.scan();

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getParam(), equalTo("name"));
        assertThat(
                alertsRaised.get(0).getAttack(),
                equalTo(
                        "field: [name], value ['; select \"java.lang.Thread.sleep\"(300) from INFORMATION_SCHEMA.SYSTEM_COLUMNS where TABLE_NAME = 'SYSTEM_COLUMNS' and COLUMN_NAME = 'TABLE_NAME' -- ]"));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_HIGH));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
    }

    @Test
    public void shouldNotAlertIfAllTimesGetLonger() throws Exception {
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
                        time += 300;
                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = this.getHttpMessage(test + "?name=test");

        this.rule.init(msg, this.parent);
        this.rule.setSleepInMs(300);

        this.rule.scan();

        assertThat(alertsRaised.size(), equalTo(0));
    }
}
