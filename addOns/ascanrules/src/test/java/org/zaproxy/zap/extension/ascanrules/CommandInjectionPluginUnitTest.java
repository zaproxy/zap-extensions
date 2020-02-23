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
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertThat;
import static org.zaproxy.zap.extension.ascanrules.utils.Constants.NULL_BYTE_CHARACTER;

import fi.iki.elonen.NanoHTTPD;
import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;
import org.apache.commons.configuration.Configuration;
import org.junit.Test;
import org.parosproxy.paros.core.scanner.Plugin;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.zaproxy.zap.extension.ruleconfig.RuleConfigParam;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;
import org.zaproxy.zap.testutils.NanoServerHandler;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/** Unit test for {@link CommandInjectionPlugin}. */
public class CommandInjectionPluginUnitTest
        extends ActiveScannerAppParamTest<CommandInjectionPlugin> {

    @Override
    protected int getRecommendMaxNumberMessagesPerParam(AttackStrength strength) {
        int recommendMax = super.getRecommendMaxNumberMessagesPerParam(strength);
        switch (strength) {
            case LOW:
                return recommendMax + 6;
            case MEDIUM:
            default:
                return recommendMax + 20;
            case HIGH:
                return recommendMax + 27;
            case INSANE:
                return recommendMax + 14;
        }
    }

    @Override
    protected CommandInjectionPlugin createScanner() {
        CommandInjectionPlugin scanner = new CommandInjectionPlugin();
        scanner.setConfig(new ZapXmlConfiguration());
        return scanner;
    }

    @Test
    public void shouldTargetLinuxTech() {
        // Given
        TechSet techSet = techSet(Tech.Linux);
        // When
        boolean targets = rule.targets(techSet);
        // Then
        assertThat(targets, is(equalTo(true)));
    }

    @Test
    public void shouldTargetMacOsTech() {
        // Given
        TechSet techSet = techSet(Tech.MacOS);
        // When
        boolean targets = rule.targets(techSet);
        // Then
        assertThat(targets, is(equalTo(true)));
    }

    @Test
    public void shouldTargetWindowsTech() {
        // Given
        TechSet techSet = techSet(Tech.Windows);
        // When
        boolean targets = rule.targets(techSet);
        // Then
        assertThat(targets, is(equalTo(true)));
    }

    @Test
    public void shouldNotTargetNonLinuxMacOsWindowsTechs() {
        // Given
        TechSet techSet = techSetWithout(Tech.Linux, Tech.MacOS, Tech.Windows);
        // When
        boolean targets = rule.targets(techSet);
        // Then
        assertThat(targets, is(equalTo(false)));
    }

    @Test(expected = NullPointerException.class)
    public void shouldFailToInitWithoutConfig() throws Exception {
        // Given
        CommandInjectionPlugin scanner = new CommandInjectionPlugin();
        // When
        scanner.init(getHttpMessage(""), parent);
        // Then = NullPointerException
    }

    @Test
    public void shouldInitWithConfig() throws Exception {
        // Given
        CommandInjectionPlugin scanner = new CommandInjectionPlugin();
        scanner.setConfig(new ZapXmlConfiguration());
        // When
        scanner.init(getHttpMessage(""), parent);
        // Then = No exception.
    }

    @Test
    public void shouldUse5SecsByDefaultForTimeBasedAttacks() throws Exception {
        // Given / When
        int time = rule.getTimeSleep();
        // Then
        assertThat(time, is(equalTo(5)));
    }

    @Test
    public void shouldUseTimeDefinedInConfigForTimeBasedAttacks() throws Exception {
        // Given
        rule.setConfig(configWithSleepRule("10"));
        // When
        rule.init(getHttpMessage(""), parent);
        // Then
        assertThat(rule.getTimeSleep(), is(equalTo(10)));
    }

    @Test
    public void shouldDefaultTo5SecsIfConfigTimeIsMalformedValueForTimeBasedAttacks()
            throws Exception {
        // Given
        rule.setConfig(configWithSleepRule("not a valid value"));
        // When
        rule.init(getHttpMessage(""), parent);
        // Then
        assertThat(rule.getTimeSleep(), is(equalTo(5)));
    }

    @Test
    public void shouldUseSpecifiedTimeInAllTimeBasedPayloads() throws Exception {
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
    public void shouldRaiseAlertIfResponseHasPasswdFileContentAndPayloadIsNullByteBased()
            throws HttpMalformedHeaderException {
        // Given
        // While checking for relevant handler in HTTPDTestServer, it checks handler
        // Name with the URI so ensure you pass URI same as ServerHandler Name
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
    public void shouldRaiseAlertIfResponseHasSystemINIFileContentAndPayloadIsNullByteBased()
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

    private static class NullByteVulnerableServerHandler extends NanoServerHandler {

        protected String param;
        protected Tech tech;

        protected static final String GENERIC_VULN_RESPONSE_NIX =
                "<!DOCTYPE html>\n"
                        + "<html>"
                        + "<head>"
                        + "<title>Page Title</title>"
                        + "</head>"
                        + "<body>"
                        + "<p>root:x:0:0:root:/root:/bin/bash\n"
                        + "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                        + "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
                        + "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
                        + "sync:x:4:65534:sync:/bin:/bin/sync\n"
                        + "</p>"
                        + "</body>"
                        + "</html>";

        protected static final String GENERIC_VULN_RESPONSE_WIN =
                "<!DOCTYPE html>\n"
                        + "<html>"
                        + "<head>"
                        + "<title>Page Title</title>"
                        + "</head>"
                        + "<body>"
                        + "<p>[drivers]\n"
                        + "wave=mmdrv.dll\n"
                        + "timer=timer.drv\n"
                        + "[fonts]\n"
                        + "</p>"
                        + "</body>"
                        + "</html>";

        public NullByteVulnerableServerHandler(String name, String param, Tech tech) {
            super(name);
            this.param = param;
            this.tech = tech;
        }

        public String getContent(IHTTPSession session) {
            String value = getFirstParamValue(session, this.param);
            if (value.contains(NULL_BYTE_CHARACTER)) {
                return this.tech.equals(Tech.Linux) || this.tech.equals(Tech.MacOS)
                        ? GENERIC_VULN_RESPONSE_NIX
                        : GENERIC_VULN_RESPONSE_WIN;
            } else {
                return "<html></html>";
            }
        }

        @Override
        protected Response serve(IHTTPSession session) {
            return newFixedLengthResponse(
                    Response.Status.OK, NanoHTTPD.MIME_HTML, getContent(session));
        }
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
