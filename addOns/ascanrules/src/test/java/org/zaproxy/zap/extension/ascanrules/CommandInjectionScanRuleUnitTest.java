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
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import fi.iki.elonen.NanoHTTPD;
import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;
import java.util.stream.Stream;
import org.apache.commons.configuration.Configuration;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.parosproxy.paros.core.scanner.Plugin;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.extension.ruleconfig.RuleConfigParam;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;
import org.zaproxy.zap.testutils.NanoServerHandler;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/** Unit test for {@link CommandInjectionScanRule}. */
class CommandInjectionScanRuleUnitTest extends ActiveScannerTest<CommandInjectionScanRule> {

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
    protected CommandInjectionScanRule createScanner() {
        CommandInjectionScanRule scanner = new CommandInjectionScanRule();
        scanner.setConfig(new ZapXmlConfiguration());
        return scanner;
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
        assertThat(tags.size(), is(equalTo(3)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A03_INJECTION.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A01_INJECTION.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.WSTG_V42_INPV_12_COMMAND_INJ.getTag()),
                is(equalTo(true)));
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
    void shouldTargetLinuxTech() {
        // Given
        TechSet techSet = techSet(Tech.Linux);
        // When
        boolean targets = rule.targets(techSet);
        // Then
        assertThat(targets, is(equalTo(true)));
    }

    @Test
    void shouldTargetMacOsTech() {
        // Given
        TechSet techSet = techSet(Tech.MacOS);
        // When
        boolean targets = rule.targets(techSet);
        // Then
        assertThat(targets, is(equalTo(true)));
    }

    @Test
    void shouldTargetWindowsTech() {
        // Given
        TechSet techSet = techSet(Tech.Windows);
        // When
        boolean targets = rule.targets(techSet);
        // Then
        assertThat(targets, is(equalTo(true)));
    }

    @Test
    void shouldNotTargetNonLinuxMacOsWindowsTechs() {
        // Given
        TechSet techSet = techSetWithout(Tech.Linux, Tech.MacOS, Tech.Windows);
        // When
        boolean targets = rule.targets(techSet);
        // Then
        assertThat(targets, is(equalTo(false)));
    }

    @Test
    void shouldFailToInitWithoutConfig() throws Exception {
        // Given
        CommandInjectionScanRule scanner = new CommandInjectionScanRule();
        HttpMessage msg = getHttpMessage("");
        // When / Then
        assertThrows(NullPointerException.class, () -> scanner.init(msg, parent));
    }

    @Test
    void shouldInitWithConfig() throws Exception {
        // Given
        CommandInjectionScanRule scanner = new CommandInjectionScanRule();
        scanner.setConfig(new ZapXmlConfiguration());
        // When / Then
        assertDoesNotThrow(() -> scanner.init(getHttpMessage(""), parent));
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
    void shouldRaiseAlertIfResponseHasPasswdFileContentAndPayloadIsNullByteBased()
            throws HttpMalformedHeaderException {
        // Given
        NullByteVulnerableServerHandler vulnServerHandler =
                new NullByteVulnerableServerHandler("/", "p", Tech.Linux);
        nano.addHandler(vulnServerHandler);
        rule.init(getHttpMessage("/?p=a"), parent);
        rule.setAttackStrength(AttackStrength.INSANE);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
    }

    @Test
    void shouldRaiseAlertIfResponseHasSystemINIFileContentAndPayloadIsNullByteBased()
            throws HttpMalformedHeaderException {
        // Given
        NullByteVulnerableServerHandler vulnServerHandler =
                new NullByteVulnerableServerHandler("/", "p", Tech.Windows);
        nano.addHandler(vulnServerHandler);
        rule.init(getHttpMessage("/?p=a"), parent);
        rule.setAttackStrength(AttackStrength.INSANE);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
    }

    @Test
    void shouldRaiseAlertIfResponseHasEscapedHtmlControlPattern()
            throws HttpMalformedHeaderException {
        // Given
        nano.addHandler(
                new NanoServerHandler("/") {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String value = getFirstParamValue(session, "p");
                        if (value == null || !value.contains("/etc/passwd")) {
                            String regularContent =
                                    "<!DOCTYPE html><html><body>Nothing to see here.</body></html>";
                            return newFixedLengthResponse(regularContent);
                        }
                        String content =
                                "<!DOCTYPE html>\n"
                                        + "<html><body>"
                                        + "root&#x3a;x&#x3a;0&#x3a;0&#x3a;root&#x3a;&#x2f;root&#x3a;&#x2f;bin&#x2f;bash<br>"
                                        + "daemon&#x3a;x&#x3a;1&#x3a;1&#x3a;daemon&#x3a;&#x2f;usr&#x2f;sbin&#x3a;&#x2f;usr&#x2f;sbin&#x2f;nologin<br>"
                                        + "bin&#x3a;x&#x3a;2&#x3a;2&#x3a;bin&#x3a;&#x2f;bin&#x3a;&#x2f;usr&#x2f;sbin&#x2f;nologin<br>"
                                        + "sys&#x3a;x&#x3a;3&#x3a;3&#x3a;sys&#x3a;&#x2f;dev&#x3a;&#x2f;usr&#x2f;sbin&#x2f;nologin<br>"
                                        + "sync&#x3a;x&#x3a;4&#x3a;65534&#x3a;sync&#x3a;&#x2f;bin&#x3a;&#x2f;bin&#x2f;sync<br>"
                                        + "</body></html>";
                        return newFixedLengthResponse(content);
                    }
                });
        rule.init(getHttpMessage("/?p=a"), parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
    }

    private static Stream<Arguments> shouldReturnRelevantTechs() {
        return Stream.of(
                Arguments.of(Tech.Windows), Arguments.of(Tech.Linux), Arguments.of(Tech.MacOS));
    }

    @ParameterizedTest
    @MethodSource("shouldReturnRelevantTechs")
    void firstPayloadShouldNotHaveParamValue(Tech targetedTech)
            throws HttpMalformedHeaderException {
        // Given
        NullByteVulnerableServerHandler vulnServerHandler =
                new NullByteVulnerableServerHandler("/", "p", targetedTech);
        nano.addHandler(vulnServerHandler);
        rule.init(getHttpMessage("/?p=a"), parent);
        rule.setAttackStrength(AttackStrength.INSANE);
        // When
        rule.scan();
        // Then
        assertFalse(httpMessagesSent.get(0).getUrlParams().first().getValue().startsWith("a"));
        assertTrue(httpMessagesSent.get(1).getUrlParams().first().getValue().startsWith("a"));
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
