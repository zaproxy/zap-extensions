/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.fail;

import fi.iki.elonen.NanoHTTPD;
import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.commons.configuration.Configuration;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.zap.extension.ruleconfig.RuleConfigParam;
import org.zaproxy.zap.testutils.NanoServerHandler;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/** Unit test for {@link CommandInjectionTimingScanRule}. */
class CommandInjectionTimingScanRuleUnitTest
        extends CommandInjectionRuleTest<CommandInjectionTimingScanRule> {

    @Override
    protected int getRecommendMaxNumberMessagesPerParam(AttackStrength strength) {
        int recommendMax = super.getRecommendMaxNumberMessagesPerParam(strength);
        switch (strength) {
            case MEDIUM:
                return recommendMax + 4;
            default:
                return recommendMax;
        }
    }

    @Override
    protected CommandInjectionTimingScanRule createScanner() {
        CommandInjectionTimingScanRule scanRule = new CommandInjectionTimingScanRule();
        scanRule.setConfig(new ZapXmlConfiguration());
        return scanRule;
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        int cwe = rule.getCweId();
        int wasc = rule.getWascId();
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(cwe, is(equalTo(78)));
        assertThat(wasc, is(equalTo(31)));
        assertThat(tags.size(), is(equalTo(15)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A03_INJECTION.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A01_INJECTION.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.WSTG_V42_INPV_12_COMMAND_INJ.getTag()),
                is(equalTo(true)));
        assertThat(tags.containsKey(CommonAlertTag.HIPAA.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(CommonAlertTag.PCI_DSS.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(CommonAlertTag.TEST_TIMING.getTag()), is(equalTo(true)));
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
                tags.get(CommonAlertTag.WSTG_V42_INPV_12_COMMAND_INJ.getTag()),
                is(equalTo(CommonAlertTag.WSTG_V42_INPV_12_COMMAND_INJ.getValue())));
    }

    @Test
    void shouldFailToInitWithoutConfig() throws Exception {
        // Given
        CommandInjectionTimingScanRule scanRule = new CommandInjectionTimingScanRule();
        HttpMessage msg = getHttpMessage("");
        // When / Then
        assertThrows(NullPointerException.class, () -> scanRule.init(msg, parent));
    }

    @Test
    void shouldInitWithConfig() {
        // Given
        CommandInjectionTimingScanRule scanRule = new CommandInjectionTimingScanRule();
        scanRule.setConfig(new ZapXmlConfiguration());
        // When / Then
        assertDoesNotThrow(() -> scanRule.init(getHttpMessage(""), parent));
    }

    @Test
    void shouldUse5SecsByDefaultForTimeBasedAttacks() {
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
        PayloadCollectorHandler payloadCollector =
                new PayloadCollectorHandler(
                        "/", "p", v -> v.contains("sleep") || v.contains("timeout"));
        nano.addHandler(payloadCollector);
        rule.setConfig(configWithSleepRule(sleepTime));
        rule.setAttackStrength(Plugin.AttackStrength.INSANE);
        rule.init(getHttpMessage("?p=v"), parent);
        // When
        rule.scan();
        // Then
        for (String payload : payloadCollector.getPayloads()) {
            assertThat(payload, not(containsString("{0}")));
            assertThat(payload, containsString(sleepTime));
        }
    }

    private static Configuration configWithSleepRule(String value) {
        Configuration config = new ZapXmlConfiguration();
        config.setProperty(RuleConfigParam.RULE_COMMON_SLEEP_TIME, value);
        return config;
    }

    @Test
    void shouldDetectTimeBasedInjection() throws HttpMalformedHeaderException {
        // Given
        Pattern sleepPattern = Pattern.compile("(?:sleep|timeout /T|start-sleep -s) (\\d+)");
        String regularContent = "<!DOCTYPE html><html><body>Nothing to see here.</body></html>";
        nano.addHandler(
                new NanoServerHandler("/") {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String value = getFirstParamValue(session, "p");
                        if (value == null) {
                            return newFixedLengthResponse(regularContent);
                        }
                        Matcher match = sleepPattern.matcher(value);
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

    @Test
    void shouldHaveExpectedExampleAlert() {
        // Given / WHen
        List<Alert> alerts = rule.getExampleAlerts();
        // Then
        assertThat(alerts.size(), is(equalTo(1)));
        Alert alert = alerts.get(0);
        assertThat(alert.getConfidence(), is(equalTo(Alert.CONFIDENCE_MEDIUM)));
        assertThat(alert.getParam(), is(equalTo("qry")));
        assertThat(alert.getAttack(), is(equalTo("sleep 5")));
        assertThat(
                alert.getOtherInfo(),
                is(
                        equalTo(
                                "The scan rule was able to control the timing "
                                        + "of the application response by sending "
                                        + "[sleep 5] to the operating system running "
                                        + "this application.")));
    }

    private static class PayloadCollectorHandler extends NanoServerHandler {

        private final String param;
        private final Predicate<String> valuePredicate;
        private final List<String> payloads;

        public PayloadCollectorHandler(
                String path, String param, Predicate<String> valuePredicate) {
            super(path);

            this.param = param;
            this.valuePredicate = valuePredicate;
            this.payloads = new ArrayList<>();
        }

        public List<String> getPayloads() {
            return payloads;
        }

        @Override
        protected Response serve(IHTTPSession session) {
            String value = getFirstParamValue(session, param);
            if (valuePredicate.test(value)) {
                payloads.add(value);
            }
            return newFixedLengthResponse(Response.Status.OK, NanoHTTPD.MIME_HTML, "Content");
        }
    }
}
