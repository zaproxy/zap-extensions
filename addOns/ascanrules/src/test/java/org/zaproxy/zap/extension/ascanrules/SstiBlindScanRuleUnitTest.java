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

import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.testutils.NanoServerHandler;

class SstiBlindScanRuleUnitTest extends ActiveScannerTest<SstiBlindScanRule> {

    @Override
    protected SstiBlindScanRule createScanner() {
        return new SstiBlindScanRule();
    }

    @Override
    protected int getRecommendMaxNumberMessagesPerParam(Plugin.AttackStrength strength) {
        int recommendMax = super.getRecommendMaxNumberMessagesPerParam(strength);
        switch (strength) {
            case LOW:
                return recommendMax + 6;
            case MEDIUM:
            case HIGH:
            case INSANE:
            default:
                return recommendMax;
        }
    }

    @Test
    void shouldAlertIfSleepTimesGetLonger() throws Exception {
        String test = "/shouldAlertIfSleepTimesGetLonger";
        Pattern sleepPattern = Pattern.compile("#\\{%x\\(sleep\\s+(\\d+)\\)\\}");

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
                            Thread.sleep(sleepInput * 1000);
                        } catch (InterruptedException e) {
                            // Ignore
                        }
                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = this.getHttpMessage(test + "?name=test");

        this.rule.init(msg, this.parent);
        this.rule.setSleepInSeconds(2);

        this.rule.scan();

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getParam(), equalTo("name"));
        assertThat(alertsRaised.get(0).getAttack(), equalTo("#{%x(sleep 2)}"));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_HIGH));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_HIGH));
    }

    @Test
    void shouldNotAlertIfAllTimesGetLonger() throws Exception {
        String test = "/shouldNotReportGeneralTimingIssue";

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
                        time += 1000;
                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = this.getHttpMessage(test + "?name=test");

        this.rule.init(msg, this.parent);
        this.rule.setSleepInSeconds(2);

        this.rule.scan();

        assertThat(alertsRaised.size(), equalTo(0));
    }
}
