/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.addon.client.pscan;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.anEmptyMap;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.withSettings;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.zaproxy.addon.commonlib.gspm.GspmPhase;
import org.zaproxy.addon.commonlib.gspm.GspmRegistry;
import org.zaproxy.addon.commonlib.gspm.GspmRule;
import org.zaproxy.addon.commonlib.gspm.GspmScanRuleRegistrar;
import org.zaproxy.zap.control.AddOn;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.I18N;

/** Unit test for {@link GspmClientPassiveScanRegistrar}. */
class GspmClientPassiveScanRegistrarUnitTest extends TestUtils {

    private ClientPassiveScanController controller;
    private List<ClientPassiveScanRule> scanRules;
    private AddOn addOn;
    private GspmScanRuleRegistrar scanRuleRegistrar;
    private GspmRegistry registry;

    @BeforeEach
    void setUp() throws Exception {
        I18N i18n = mock(I18N.class, withSettings().strictness(Strictness.LENIENT));
        given(i18n.getString(anyString())).willReturn("");
        given(i18n.getString(anyString(), any())).willReturn("");
        Constant.messages = i18n;

        scanRules = new ArrayList<>();
        controller = mock(ClientPassiveScanController.class);
        given(controller.getAllScanRules()).willAnswer(inv -> List.copyOf(scanRules));
        addOn = mock(AddOn.class, withSettings().strictness(Strictness.LENIENT));
        given(addOn.getName()).willReturn("Client Side Integration");
        given(addOn.getStatus()).willReturn(AddOn.Status.beta);

        GspmClientPassiveScanRegistrar registrar =
                new GspmClientPassiveScanRegistrar(controller, addOn);
        scanRuleRegistrar = (GspmScanRuleRegistrar) getField(registrar, "scanRuleRegistrar");
        registry = new GspmRegistry();
    }

    @AfterAll
    static void cleanUp() {
        Constant.messages = null;
    }

    @Test
    void shouldRegisterAllRules() {
        // Given
        scanRules.add(scanRule(120000, "Rule A", true));
        scanRules.add(scanRule(120001, "Rule B", false));

        // When
        scanRuleRegistrar.registerRulesWithGspm(registry);

        // Then
        List<GspmRule> rules = registry.getRulesByTool(GspmClientPassiveScanRegistrar.TOOL);
        assertThat(rules, hasSize(2));
        assertThat(rules.stream().map(GspmRule::getId).toList(), contains(120000, 120001));
    }

    @Test
    void shouldUnregisterAllRules() {
        // Given
        scanRules.add(scanRule(120000, "Rule A", true));
        scanRuleRegistrar.registerRulesWithGspm(registry);

        // When
        scanRuleRegistrar.unregisterRulesFromGspm(registry);

        // Then
        assertThat(registry.getRulesByTool(GspmClientPassiveScanRegistrar.TOOL), hasSize(0));
    }

    @Test
    void shouldMapRuleDetails() {
        // Given
        scanRules.add(scanRule(120000, "Rule A", true));

        // When
        GspmRule rule = registerSingleRule();

        // Then
        assertThat(rule.getId(), is(120000));
        assertThat(rule.getName(), is("Rule A"));
        assertThat(rule.getTool(), is(GspmClientPassiveScanRegistrar.TOOL));
        assertThat(rule.getPhase(), is(GspmPhase.PASSIVE));
        assertThat(rule.getCategories(), hasSize(1));
        assertThat(rule.getCategories().get(0).id(), is("client"));
        assertThat(rule.getAlertTags(), is(anEmptyMap()));
        assertThat(rule.getAttackStrength(), is(nullValue()));
        assertThat(rule.getStatus(), is(AddOn.Status.beta));
        assertThat(rule.getAddOnName(), is("Client Side Integration"));
    }

    @Test
    void shouldReportEnabledRuleAsEnabledWithMediumThreshold() {
        // Given
        scanRules.add(scanRule(120000, "Rule A", true));

        // When
        GspmRule rule = registerSingleRule();

        // Then
        assertThat(rule.isEnabled(), is(true));
        assertThat(rule.getAlertThreshold(), is(AlertThreshold.MEDIUM));
    }

    @Test
    void shouldReportDisabledRuleAsDisabledWithOffThreshold() {
        // Given
        scanRules.add(scanRule(120000, "Rule A", false));

        // When
        GspmRule rule = registerSingleRule();

        // Then
        assertThat(rule.isEnabled(), is(false));
        assertThat(rule.getAlertThreshold(), is(AlertThreshold.OFF));
    }

    @Test
    void shouldDelegateSetEnabledToRule() {
        // Given
        ClientPassiveScanRule scanRule = scanRule(120000, "Rule A", true);
        scanRules.add(scanRule);
        GspmRule rule = registerSingleRule();

        // When
        rule.setEnabled(false);

        // Then
        verify(scanRule).setEnabled(false);
    }

    @Test
    void shouldDisableRuleWhenThresholdSetToOff() {
        // Given
        ClientPassiveScanRule scanRule = scanRule(120000, "Rule A", true);
        scanRules.add(scanRule);
        GspmRule rule = registerSingleRule();

        // When
        rule.setAlertThreshold(AlertThreshold.OFF);

        // Then
        verify(scanRule).setEnabled(false);
    }

    @Test
    void shouldDisableRuleWhenThresholdSetToNull() {
        // Given
        ClientPassiveScanRule scanRule = scanRule(120000, "Rule A", true);
        scanRules.add(scanRule);
        GspmRule rule = registerSingleRule();

        // When
        rule.setAlertThreshold(null);

        // Then
        verify(scanRule).setEnabled(false);
    }

    @ParameterizedTest
    @EnumSource(
            value = AlertThreshold.class,
            names = {"OFF"},
            mode = EnumSource.Mode.EXCLUDE)
    void shouldEnableRuleWhenThresholdSetToNonOff(AlertThreshold threshold) {
        // Given
        ClientPassiveScanRule scanRule = scanRule(120000, "Rule A", false);
        scanRules.add(scanRule);
        GspmRule rule = registerSingleRule();

        // When
        rule.setAlertThreshold(threshold);

        // Then
        verify(scanRule).setEnabled(true);
    }

    private GspmRule registerSingleRule() {
        scanRuleRegistrar.registerRulesWithGspm(registry);
        return registry.getRulesByTool(GspmClientPassiveScanRegistrar.TOOL).get(0);
    }

    private static ClientPassiveScanRule scanRule(int id, String name, boolean enabled) {
        ClientPassiveScanRule rule =
                mock(ClientPassiveScanRule.class, withSettings().strictness(Strictness.LENIENT));
        given(rule.getId()).willReturn(id);
        given(rule.getName()).willReturn(name);
        given(rule.isEnabled()).willReturn(enabled);
        return rule;
    }

    private static Object getField(Object target, String name) throws Exception {
        Field field = target.getClass().getDeclaredField(name);
        field.setAccessible(true);
        return field.get(target);
    }
}
