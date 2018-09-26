/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP development team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.ascanrules;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

import org.apache.commons.configuration.Configuration;
import org.junit.Test;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/**
 * Unit test for {@link CommandInjectionPlugin}.
 */
public class CommandInjectionPluginUnitTest extends ActiveScannerAppParamTest<CommandInjectionPlugin> {

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
            return recommendMax + 22;
        case INSANE:
            return recommendMax;
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
    public void shouldDefaultTo5SecsIfConfigTimeIsMalformedValueForTimeBasedAttacks() throws Exception {
        // Given
        rule.setConfig(configWithSleepRule("not a valid value"));
        // When
        rule.init(getHttpMessage(""), parent);
        // Then
        assertThat(rule.getTimeSleep(), is(equalTo(5)));
    }

    private static Configuration configWithSleepRule(String value) {
        Configuration config = new ZapXmlConfiguration();
        // TODO Replace with RuleConfigParam.RULE_COMMON_SLEEP_TIME once available.
        config.setProperty("rules.common.sleep", value);
        return config;
    }

}
