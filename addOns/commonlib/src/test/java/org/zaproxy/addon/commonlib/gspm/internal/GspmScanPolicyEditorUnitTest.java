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
package org.zaproxy.addon.commonlib.gspm.internal;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.sameInstance;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import java.awt.Component;
import java.awt.Container;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.zaproxy.addon.commonlib.ExtensionCommonlib;
import org.zaproxy.addon.commonlib.gspm.GspmCategory;
import org.zaproxy.addon.commonlib.gspm.GspmPhase;
import org.zaproxy.addon.commonlib.gspm.GspmPolicy;
import org.zaproxy.addon.commonlib.gspm.GspmRegistry;
import org.zaproxy.addon.commonlib.gspm.GspmRule;
import org.zaproxy.addon.commonlib.gspm.GspmRuleSet;
import org.zaproxy.zap.extension.ascan.ScanPolicy;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/** Unit test for {@link GspmScanPolicyEditor}. */
class GspmScanPolicyEditorUnitTest extends TestUtils {

    private GspmRegistry registry;
    private GspmPolicy policy;

    @BeforeEach
    void setUp() {
        registry = new GspmRegistry();
        policy = new GspmPolicy("Policy");
        policy.findOrCreateCategoryRuleSet("phase.active").setThresholdEnum(AlertThreshold.HIGH);
        policy.setRuleThreshold(100, "Rule", AlertThreshold.LOW);
        registry.addPolicy(policy);
    }

    @AfterEach
    void cleanUp() {
        Constant.messages = null;
    }

    @Test
    void shouldCreateWorkingCopyWithSameNameAndRuleSets() throws Exception {
        // Given / When
        GspmPolicy copy = GspmScanPolicyEditor.createWorkingCopy(policy);
        // Then
        assertThat(copy, is(not(sameInstance(policy))));
        assertThat(copy.getName(), is(equalTo("Policy")));
        assertThat(yaml(copy), is(equalTo(yaml(policy))));
        assertThat(registry.getPolicy("Policy"), is(sameInstance(policy)));
    }

    @Test
    void shouldNotChangePolicyWhenEditingWorkingCopy() throws Exception {
        // Given
        GspmPolicy copy = GspmScanPolicyEditor.createWorkingCopy(policy);
        // When
        copy.findOrCreateCategoryRuleSet("phase.active").setThresholdEnum(AlertThreshold.OFF);
        copy.setRuleThreshold(200, "Other", AlertThreshold.HIGH);
        // Then
        assertThat(
                policy.getCategoryThreshold("phase.active"),
                is(equalTo(Optional.of(AlertThreshold.HIGH))));
        assertThat(yaml(policy), is(not(equalTo(yaml(copy)))));
    }

    @Test
    void shouldEditWorkingCopyOfSelectedPolicy() throws Exception {
        // Given
        GspmScanPolicyEditor editor = new GspmScanPolicyEditor(registry);
        // When
        editor.setScanPolicy(scanPolicy("Policy"));
        // Then
        assertThat(editor.getWorkingCopy(), is(not(sameInstance(policy))));
        assertThat(yaml(editor.getWorkingCopy()), is(equalTo(yaml(policy))));
    }

    @Test
    void shouldDiscardEditsWhenPolicySetAgain() throws Exception {
        // Given
        GspmScanPolicyEditor editor = new GspmScanPolicyEditor(registry);
        editor.setScanPolicy(scanPolicy("Policy"));
        editor.getWorkingCopy().setRuleThreshold(200, "Other", AlertThreshold.HIGH);
        // When
        editor.setScanPolicy(scanPolicy("Policy"));
        // Then
        assertThat(yaml(editor.getWorkingCopy()), is(equalTo(yaml(policy))));
    }

    @Test
    void shouldUseSelectedScanPolicyIfNotInRegistry() throws Exception {
        // Given
        GspmScanPolicyEditor editor = new GspmScanPolicyEditor(registry);
        ScanPolicy scanPolicy = scanPolicy("Unknown");
        // When
        editor.setScanPolicy(scanPolicy);
        // Then
        assertThat(editor.getWorkingCopy(), is(nullValue()));
        assertThat(editor.getScanPolicy(), is(sameInstance(scanPolicy)));
    }

    @Test
    void shouldSelectNameOfPolicySet() throws Exception {
        // Given
        GspmScanPolicyEditor editor = new GspmScanPolicyEditor(registry);
        // When
        editor.setScanPolicy(scanPolicy("Policy"));
        // Then
        assertThat(editor.getSelectedPolicyName(), is(equalTo("Policy")));
    }

    @Test
    void shouldKeepPolicyNameIfNotChanged() throws Exception {
        // Given
        GspmScanPolicyEditor editor = new GspmScanPolicyEditor(registry);
        editor.setScanPolicy(scanPolicy("Policy"));
        // When
        editor.workingCopyChanged();
        // Then
        assertThat(editor.getSelectedPolicyName(), is(equalTo("Policy")));
    }

    @Test
    void shouldClearPolicyNameWhenRuleChanged() throws Exception {
        // Given
        GspmScanPolicyEditor editor = new GspmScanPolicyEditor(registry);
        editor.setScanPolicy(scanPolicy("Policy"));
        editor.getWorkingCopy().setRuleThreshold(100, "Rule", AlertThreshold.OFF);
        // When
        editor.workingCopyChanged();
        // Then
        assertThat(editor.getSelectedPolicyName(), is(nullValue()));
    }

    @Test
    void shouldClearPolicyNameWhenRuleSetAdded() throws Exception {
        // Given
        GspmScanPolicyEditor editor = new GspmScanPolicyEditor(registry);
        editor.setScanPolicy(scanPolicy("Policy"));
        GspmRuleSet ruleSet = new GspmRuleSet();
        ruleSet.setName("Tag");
        ruleSet.setTags(List.of("OWASP_2021_A03"));
        editor.getWorkingCopy().addRuleSet(ruleSet);
        // When
        editor.workingCopyChanged();
        // Then
        assertThat(editor.getSelectedPolicyName(), is(nullValue()));
    }

    @Test
    void shouldLoadOtherPolicyDiscardingEdits() throws Exception {
        // Given
        GspmPolicy other = new GspmPolicy("Other");
        other.setRuleThreshold(300, "Other Rule", AlertThreshold.HIGH);
        registry.addPolicy(other);
        GspmScanPolicyEditor editor = new GspmScanPolicyEditor(registry);
        editor.setScanPolicy(scanPolicy("Policy"));
        editor.getWorkingCopy().setRuleThreshold(100, "Rule", AlertThreshold.OFF);
        editor.workingCopyChanged();
        // When
        editor.loadPolicy("Other");
        // Then
        assertThat(editor.getSelectedPolicyName(), is(equalTo("Other")));
        assertThat(editor.getWorkingCopy().getName(), is(equalTo("Other")));
        assertThat(yaml(editor.getWorkingCopy()), is(equalTo(yaml(other))));
    }

    @Test
    void shouldNotSelectNameOfUnknownPolicy() throws Exception {
        // Given
        GspmScanPolicyEditor editor = new GspmScanPolicyEditor(registry);
        // When
        editor.loadPolicy("Unknown");
        // Then
        assertThat(editor.getSelectedPolicyName(), is(nullValue()));
    }

    @Test
    void shouldSortPolicyNamesIgnoringCase() {
        // Given
        registry.addPolicy(new GspmPolicy("alpha"));
        registry.addPolicy(new GspmPolicy("Zulu"));
        registry.addPolicy(new GspmPolicy("beta"));
        GspmScanPolicyEditor editor = new GspmScanPolicyEditor(registry);
        // When
        List<String> names = editor.getSortedPolicyNames();
        // Then
        assertThat(names, is(equalTo(List.of("alpha", "beta", "Policy", "Zulu"))));
    }

    @Test
    void shouldKeepWorkingCopyOnRefreshIfNothingChanged() throws Exception {
        // Given
        GspmScanPolicyEditor editor = new GspmScanPolicyEditor(registry);
        editor.setScanPolicy(scanPolicy("Policy"));
        GspmPolicy copy = editor.getWorkingCopy();
        // When
        editor.refresh();
        // Then
        assertThat(editor.getWorkingCopy(), is(sameInstance(copy)));
    }

    @Test
    void shouldReloadOnRefreshIfPolicyChangedElsewhere() throws Exception {
        // Given
        GspmScanPolicyEditor editor = new GspmScanPolicyEditor(registry);
        editor.setScanPolicy(scanPolicy("Policy"));
        policy.setRuleThreshold(200, "Other", AlertThreshold.HIGH);
        // When
        editor.refresh();
        // Then
        assertThat(editor.getSelectedPolicyName(), is(equalTo("Policy")));
        assertThat(yaml(editor.getWorkingCopy()), is(equalTo(yaml(policy))));
    }

    @Test
    void shouldReloadOnRefreshIfRuleRegistered() throws Exception {
        // Given
        GspmScanPolicyEditor editor = new GspmScanPolicyEditor(registry);
        editor.setScanPolicy(scanPolicy("Policy"));
        GspmPolicy copy = editor.getWorkingCopy();
        registry.registerRule(activeRule(100, AlertThreshold.MEDIUM));
        // When
        editor.refresh();
        // Then
        assertThat(editor.getWorkingCopy(), is(not(sameInstance(copy))));
    }

    @Test
    void shouldKeepEditsOnRefreshEvenIfPolicyChangedElsewhere() throws Exception {
        // Given
        GspmScanPolicyEditor editor = new GspmScanPolicyEditor(registry);
        editor.setScanPolicy(scanPolicy("Policy"));
        editor.getWorkingCopy().setRuleThreshold(100, "Rule", AlertThreshold.OFF);
        editor.workingCopyChanged();
        GspmPolicy copy = editor.getWorkingCopy();
        policy.setRuleThreshold(200, "Other", AlertThreshold.HIGH);
        // When
        editor.refresh();
        // Then
        assertThat(editor.getWorkingCopy(), is(sameInstance(copy)));
        assertThat(editor.getSelectedPolicyName(), is(nullValue()));
    }

    @Test
    void shouldClearTreeOnRefreshIfPolicyRemoved() throws Exception {
        // Given
        GspmScanPolicyEditor editor = new GspmScanPolicyEditor(registry);
        editor.setScanPolicy(scanPolicy("Policy"));
        registry.removePolicy("Policy");
        // When
        editor.refresh();
        // Then
        assertThat(editor.getWorkingCopy(), is(nullValue()));
        assertThat(editor.getSelectedPolicyName(), is(nullValue()));
    }

    @Test
    void shouldShowRulesOfPolicyLoadedInPanel() throws Exception {
        // Given
        mockMessages(new ExtensionCommonlib());
        registry.registerRule(activeRule(100, AlertThreshold.MEDIUM));
        GspmPolicy other = new GspmPolicy("Other");
        registry.addPolicy(other);
        GspmScanPolicyEditor editor = new GspmScanPolicyEditor(registry);
        editor.loadPolicy("Other");
        Container panel = (Container) editor.getPanel();
        List<AlertThreshold> before = shownThresholds(panel);
        // When
        editor.loadPolicy("Policy");
        // Then
        assertThat(before, is(equalTo(List.of(AlertThreshold.MEDIUM, AlertThreshold.MEDIUM))));
        assertThat(
                shownThresholds(panel),
                is(equalTo(List.of(AlertThreshold.LOW, AlertThreshold.LOW))));
    }

    @Test
    void shouldSavePolicyShownWhenLoaded() {
        // Given
        GspmParam param = param();
        GspmScanPolicyEditor editor = new GspmScanPolicyEditor(registry, param);
        // When
        editor.setScanPolicy(scanPolicy("Policy"));
        // Then
        assertThat(param.getState(), is(equalTo(new GspmParam.State("Policy", false, null, null))));
    }

    @Test
    void shouldRestoreEditedPolicyInNewEditor() throws Exception {
        // Given
        GspmParam param = param();
        GspmScanPolicyEditor editor = new GspmScanPolicyEditor(registry, param);
        editor.setScanPolicy(scanPolicy("Policy"));
        editor.getWorkingCopy().setRuleThreshold(200, "Other", AlertThreshold.HIGH);
        editor.workingCopyChanged();
        String edited = yaml(editor.getWorkingCopy());
        GspmScanPolicyEditor newEditor = new GspmScanPolicyEditor(registry, param);
        // When
        newEditor.setScanPolicy(scanPolicy("Unknown"));
        // Then
        assertThat(newEditor.getSelectedPolicyName(), is(nullValue()));
        assertThat(newEditor.getWorkingCopy().getName(), is(equalTo("Policy")));
        assertThat(yaml(newEditor.getWorkingCopy()), is(equalTo(edited)));
        assertThat(yaml(policy), is(not(equalTo(edited))));
    }

    @Test
    void shouldSaveFurtherEditsAfterNameCleared() throws Exception {
        // Given
        GspmParam param = param();
        GspmScanPolicyEditor editor = new GspmScanPolicyEditor(registry, param);
        editor.setScanPolicy(scanPolicy("Policy"));
        editor.getWorkingCopy().setRuleThreshold(200, "Other", AlertThreshold.HIGH);
        editor.workingCopyChanged();
        // When
        editor.getWorkingCopy().setRuleThreshold(300, "Another", AlertThreshold.OFF);
        editor.workingCopyChanged();
        // Then
        GspmScanPolicyEditor newEditor = new GspmScanPolicyEditor(registry, param);
        newEditor.setScanPolicy(scanPolicy("Policy"));
        assertThat(yaml(newEditor.getWorkingCopy()), is(equalTo(yaml(editor.getWorkingCopy()))));
    }

    @Test
    void shouldRestoreUneditedPolicyAsItIsNow() throws Exception {
        // Given
        GspmParam param = param();
        new GspmScanPolicyEditor(registry, param).setScanPolicy(scanPolicy("Policy"));
        policy.setRuleThreshold(200, "Other", AlertThreshold.HIGH);
        GspmScanPolicyEditor newEditor = new GspmScanPolicyEditor(registry, param);
        // When
        newEditor.setScanPolicy(scanPolicy("Unknown"));
        // Then
        assertThat(newEditor.getSelectedPolicyName(), is(equalTo("Policy")));
        assertThat(yaml(newEditor.getWorkingCopy()), is(equalTo(yaml(policy))));
    }

    @Test
    void shouldSaveDefaultPolicyWithState() {
        // Given
        registry.addPolicy(new GspmPolicy("Other"));
        registry.setCurrentPolicy("Other");
        GspmParam param = param();
        GspmScanPolicyEditor editor = new GspmScanPolicyEditor(registry, param);
        // When
        editor.setScanPolicy(scanPolicy("Policy"));
        // Then
        assertThat(
                param.getState(), is(equalTo(new GspmParam.State("Policy", false, null, "Other"))));
    }

    @Test
    void shouldNotRestoreEditedPolicyIfDefaultPolicyChanged() {
        // Given
        registry.addPolicy(new GspmPolicy("Other"));
        registry.setCurrentPolicy("Policy");
        GspmParam param = param();
        GspmScanPolicyEditor editor = new GspmScanPolicyEditor(registry, param);
        editor.setScanPolicy(scanPolicy("Policy"));
        editor.getWorkingCopy().setRuleThreshold(200, "Other", AlertThreshold.HIGH);
        editor.workingCopyChanged();
        registry.setCurrentPolicy("Other");
        GspmScanPolicyEditor newEditor = new GspmScanPolicyEditor(registry, param);
        // When
        newEditor.setScanPolicy(scanPolicy("Other"));
        // Then
        assertThat(newEditor.getSelectedPolicyName(), is(equalTo("Other")));
    }

    @Test
    void shouldUseSelectedPolicyIfSavedOneRemoved() {
        // Given
        GspmParam param = param();
        param.setState(new GspmParam.State("Removed", false, null, null));
        registry.addPolicy(new GspmPolicy("Other"));
        GspmScanPolicyEditor editor = new GspmScanPolicyEditor(registry, param);
        // When
        editor.setScanPolicy(scanPolicy("Other"));
        // Then
        assertThat(editor.getSelectedPolicyName(), is(equalTo("Other")));
    }

    @Test
    void shouldRestoreOnlyTheFirstTime() {
        // Given
        GspmParam param = param();
        registry.addPolicy(new GspmPolicy("Other"));
        new GspmScanPolicyEditor(registry, param).setScanPolicy(scanPolicy("Policy"));
        GspmScanPolicyEditor editor = new GspmScanPolicyEditor(registry, param);
        editor.setScanPolicy(scanPolicy("Other"));
        // When
        editor.setScanPolicy(scanPolicy("Other"));
        // Then
        assertThat(editor.getSelectedPolicyName(), is(equalTo("Other")));
    }

    private static GspmParam param() {
        GspmParam param = new GspmParam();
        param.load(new ZapXmlConfiguration());
        return param;
    }

    /** The thresholds shown by all the rule panels of the tree, in tree order. */
    private static List<AlertThreshold> shownThresholds(Container container) throws Exception {
        List<AlertThreshold> thresholds = new ArrayList<>();
        Field field = GspmRulesPanel.class.getDeclaredField("tableModel");
        field.setAccessible(true);
        for (Component c : container.getComponents()) {
            if (c instanceof GspmRulesPanel rulesPanel) {
                GspmRuleTableModel model = (GspmRuleTableModel) field.get(rulesPanel);
                model.getRules().forEach(r -> thresholds.add(r.getAlertThreshold()));
            } else if (c instanceof Container child) {
                thresholds.addAll(shownThresholds(child));
            }
        }
        return thresholds;
    }

    private static GspmRule activeRule(int id, AlertThreshold threshold) {
        GspmRule rule = mock(GspmRule.class, withSettings().strictness(Strictness.LENIENT));
        given(rule.getId()).willReturn(id);
        given(rule.getName()).willReturn("Rule");
        given(rule.getTool()).willReturn("ascan");
        given(rule.getPhase()).willReturn(GspmPhase.ACTIVE);
        given(rule.getCategories()).willReturn(List.of(new GspmCategory("inject", "Injection")));
        given(rule.getAlertTags()).willReturn(Map.of());
        given(rule.getAlertThreshold()).willReturn(threshold);
        given(rule.getAttackStrength()).willReturn(AttackStrength.MEDIUM);
        return rule;
    }

    private static String yaml(GspmPolicy policy) throws Exception {
        return GspmPolicy.YAML_MAPPER.writeValueAsString(policy.getRuleSets());
    }

    private static ScanPolicy scanPolicy(String name) {
        ScanPolicy scanPolicy =
                mock(ScanPolicy.class, withSettings().strictness(Strictness.LENIENT));
        given(scanPolicy.getName()).willReturn(name);
        return scanPolicy;
    }
}
