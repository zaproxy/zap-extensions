/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;

import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Plugin;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.testutils.NanoServerHandler;

/** Unit test for {@link MongoDbInjectionScanRule}. */
class MongoDbInjectionScanRuleUnitTest extends ActiveScannerTest<MongoDbInjectionScanRule> {

    @Override
    protected MongoDbInjectionScanRule createScanner() {
        return new MongoDbInjectionScanRule();
    }

    @Override
    protected int getRecommendMaxNumberMessagesPerParam(Plugin.AttackStrength strength) {
        switch (strength) {
            case LOW:
                return NUMBER_MSGS_ATTACK_STRENGTH_LOW + 11;
            case MEDIUM:
            default:
                return NUMBER_MSGS_ATTACK_STRENGTH_MEDIUM + 10;
            case HIGH:
                return NUMBER_MSGS_ATTACK_STRENGTH_HIGH;
            case INSANE:
                return NUMBER_MSGS_ATTACK_STRENGTH_INSANE;
        }
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        int cwe = rule.getCweId();
        int wasc = rule.getWascId();
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(cwe, is(equalTo(943)));
        assertThat(wasc, is(equalTo(19)));
        assertThat(tags.size(), is(equalTo(3)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A03_INJECTION.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A01_INJECTION.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.WSTG_V42_INPV_05_SQLI.getTag()), is(equalTo(true)));
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
    void shouldDetectTimeBasedInjection() throws HttpMalformedHeaderException {
        // Given
        Pattern sleepPattern = Pattern.compile("0\\s+\\|\\|\\s+sleep\\((\\d+)(?:\\.\\d+)?\\)");
        String regularContent = "<!DOCTYPE html><html><body>Nothing to see here.</body></html>";
        Set<String> payloadSet = new HashSet<>();
        nano.addHandler(
                new NanoServerHandler("/") {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String value = getFirstParamValue(session, "p");
                        if (value == null) {
                            return newFixedLengthResponse(regularContent);
                        }
                        if (value.contains("sleep(")) {
                            payloadSet.add(value);
                        }
                        Matcher match = sleepPattern.matcher(value);
                        if (!match.find()) {
                            return newFixedLengthResponse(regularContent);
                        }
                        try {
                            int sleepInput = Integer.parseInt(match.group(1));
                            Thread.sleep(sleepInput * 1000L);
                        } catch (InterruptedException ex) {
                            // Ignore
                        }
                        return newFixedLengthResponse(regularContent);
                    }
                });
        rule.init(getHttpMessage("/?p=a"), parent);
        // When
        rule.scan();
        // Then
        assertThat(payloadSet, hasSize(greaterThanOrEqualTo(10)));
        assertThat(alertsRaised, hasSize(1));
        assertThat(sleepPattern.matcher(alertsRaised.get(0).getAttack()).find(), is(true));
    }

    @Test
    void shouldNotAlertIfAllTimesGetLonger() throws Exception {
        String test = "/shouldNotReportGeneralTimingIssue/";

        this.nano.addHandler(
                new NanoServerHandler(test) {
                    private int time = 100;

                    @Override
                    protected Response serve(IHTTPSession session) {
                        String response =
                                "<!DOCTYPE html><html><body>Nothing to see here.</body></html>";
                        try {
                            if (getFirstParamValue(session, "name").contains("sleep(")) {
                                Thread.sleep(time);
                                time += 1000;
                            }

                        } catch (InterruptedException e) {
                            // Ignore
                        }
                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = this.getHttpMessage(test + "?name=test");

        this.rule.init(msg, this.parent);
        this.rule.scan();

        assertThat(alertsRaised.size(), equalTo(0));
    }
}
