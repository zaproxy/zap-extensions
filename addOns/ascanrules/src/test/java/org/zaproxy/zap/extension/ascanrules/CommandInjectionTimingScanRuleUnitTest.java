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
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.fail;

import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import java.util.function.Predicate;
import org.apache.commons.configuration.Configuration;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.ruleconfig.RuleConfigParam;
import org.zaproxy.zap.testutils.NanoServerHandler;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/** Unit test for {@link CommandInjectionScanRule}. */
class CommandInjectionTimingScanRuleUnitTest
        extends ActiveScannerTest<CommandInjectionTimingScanRule> {

    @Override
    protected int getRecommendMaxNumberMessagesPerParam(AttackStrength strength) {
        int recommendMax = super.getRecommendMaxNumberMessagesPerParam(strength);
        switch (strength) {
            case LOW:
                return recommendMax + 9;
            case MEDIUM:
            default:
                return recommendMax + 23;
            case HIGH:
                return recommendMax + 30;
            case INSANE:
                return recommendMax + 17;
        }
    }

    @Override
    protected CommandInjectionTimingScanRule createScanner() {
        CommandInjectionTimingScanRule scanner = new CommandInjectionTimingScanRule();
        scanner.setConfig(new ZapXmlConfiguration());
        return scanner;
    }

    @Test
    void shouldFailToInitWithoutConfig() throws Exception {
        // Given
        CommandInjectionTimingScanRule scanner = new CommandInjectionTimingScanRule();
        HttpMessage msg = getHttpMessage("");
        // When / Then
        assertThrows(NullPointerException.class, () -> scanner.init(msg, parent));
    }

    @Test
    void shouldUse5SecsByDefaultForTimeBasedAttacks() throws Exception {
        // Given / When
        int time = rule.getTimeSleep();
        // Then
        assertThat(time, is(equalTo(5)));
    }

    @Test
    void shouldUseTimeDefinedInConfigForTimeBasedAttacks() throws Exception {
        // Given
        rule.setConfig(configWithSleepRule("10"));
        // When
        rule.init(getHttpMessage(""), parent);
        // Then
        assertThat(rule.getTimeSleep(), is(equalTo(10)));
    }

    @Test
    void shouldDefaultTo5SecsIfConfigTimeIsMalformedValueForTimeBasedAttacks() throws Exception {
        // Given
        rule.setConfig(configWithSleepRule("not a valid value"));
        // When
        rule.init(getHttpMessage(""), parent);
        // Then
        assertThat(rule.getTimeSleep(), is(equalTo(5)));
    }

    @Test
    void shouldUseSpecifiedTimeInAllTimeBasedPayloads() throws Exception {
        // Given
        String sleepTime = "987";
        CommandInjectionTimingScanRuleUnitTest.PayloadCollectorHandler payloadCollector =
                new CommandInjectionTimingScanRuleUnitTest.PayloadCollectorHandler(
                        "/", "p", v -> v.contains("sleep") || v.contains("timeout"));
        nano.addHandler(payloadCollector);
        rule.setConfig(configWithSleepRule(sleepTime));
        rule.setAttackStrength(AttackStrength.INSANE);
        rule.init(getHttpMessage("?p=v"), parent);
        // When
        rule.scan();
        // Then
        for (String payload : payloadCollector.getPayloads()) {
            assertThat(payload, not(containsString("{0}")));
            assertThat(payload, containsString(sleepTime));
        }
    }

    @Test
    void shouldDetectTimeBasedInjection()
            throws org.parosproxy.paros.network.HttpMalformedHeaderException {
        // Given
        java.util.regex.Pattern sleepPattern =
                java.util.regex.Pattern.compile("(?:sleep|timeout /T|start-sleep -s) (\\d+)");
        String regularContent = "<!DOCTYPE html><html><body>Nothing to see here.</body></html>";
        nano.addHandler(
                new NanoServerHandler("/") {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String value = getFirstParamValue(session, "p");
                        if (value == null) {
                            return newFixedLengthResponse(regularContent);
                        }
                        java.util.regex.Matcher match = sleepPattern.matcher(value);
                        if (!match.find()) {
                            return newFixedLengthResponse(regularContent);
                        }
                        try {
                            int sleepInput = Integer.parseInt(match.group(1));
                            Thread.sleep(sleepInput * 1000L);
                        } catch (InterruptedException ex) {
                            fail("failed to sleep thread for time-based command injection");
                        }
                        return newFixedLengthResponse(regularContent);
                    }
                });
        rule.init(getHttpMessage("/?p=a"), parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(sleepPattern.matcher(alertsRaised.get(0).getAttack()).find(), is(true));
    }

    private static Configuration configWithSleepRule(String value) {
        Configuration config = new ZapXmlConfiguration();
        config.setProperty(RuleConfigParam.RULE_COMMON_SLEEP_TIME, value);
        return config;
    }

    private static class PayloadCollectorHandler extends NanoServerHandler {

        private final String param;
        private final Predicate<String> valuePredicate;
        private final java.util.List<String> payloads;

        public PayloadCollectorHandler(
                String path, String param, Predicate<String> valuePredicate) {
            super(path);

            this.param = param;
            this.valuePredicate = valuePredicate;
            this.payloads = new java.util.ArrayList<>();
        }

        public java.util.List<String> getPayloads() {
            return payloads;
        }

        @Override
        protected Response serve(IHTTPSession session) {
            String value = getFirstParamValue(session, param);
            if (valuePredicate.test(value)) {
                payloads.add(value);
            }
            return newFixedLengthResponse(
                    Response.Status.OK, fi.iki.elonen.NanoHTTPD.MIME_HTML, "Content");
        }
    }
}
