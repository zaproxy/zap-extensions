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
package org.zaproxy.addon.commonlib.gspm;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.zaproxy.addon.commonlib.ExtensionCommonlib;
import org.zaproxy.addon.commonlib.gspm.GspmRegistry.RegistryListener;
import org.zaproxy.zap.testutils.TestUtils;

@SuppressWarnings("OptionalGetWithoutIsPresent")
class GspmRegistryUnitTest extends TestUtils {

    private GspmRegistry registry;

    @BeforeAll
    static void setupMessages() {
        // GspmRegistry.getDefaultPolicyName() (used by loadPolicies()) reads Constant.messages.
        mockMessages(new ExtensionCommonlib());
    }

    @AfterAll
    static void cleanUpMessages() {
        Constant.messages = null;
    }

    @BeforeEach
    void setUp() {
        registry = new GspmRegistry();
    }

    @Nested
    class RuleRegistration {

        @Test
        void shouldStartEmpty() {
            assertThat(registry.getAllRules(), is(empty()));
        }

        @Test
        void shouldRegisterRule() {
            GspmRule rule = rule("pscan", 10020);

            registry.registerRule(rule);

            assertThat(registry.getAllRules(), contains(rule));
        }

        @Test
        void shouldRegisterMultipleRulesFromDifferentTools() {
            GspmRule ascanRule = rule("ascan", 1);
            GspmRule pscanRule = rule("pscan", 2);

            registry.registerRule(ascanRule);
            registry.registerRule(pscanRule);

            assertThat(registry.getAllRules(), hasSize(2));
        }

        @Test
        void shouldRegisterMultipleRulesFromSameToolWithDifferentIds() {
            GspmRule rule1 = rule("pscan", 10020);
            GspmRule rule2 = rule("pscan", 10021);

            registry.registerRule(rule1);
            registry.registerRule(rule2);

            assertThat(registry.getAllRules(), hasSize(2));
        }

        @Test
        void shouldRejectDuplicateId() {
            registry.registerRule(rule("pscan", 10020));

            assertThrows(
                    IllegalArgumentException.class,
                    () -> registry.registerRule(rule("ascan", 10020)));
        }

        @Test
        void shouldRejectNullRule() {
            assertThrows(NullPointerException.class, () -> registry.registerRule(null));
        }

        @Test
        void shouldUnregisterRule() {
            GspmRule rule = rule("pscan", 10020);
            registry.registerRule(rule);

            registry.unregisterRule(rule);

            assertThat(registry.getAllRules(), is(empty()));
        }

        @Test
        void shouldBeNoOpWhenUnregisteringUnknownRule() {
            registry.unregisterRule(rule("pscan", 10020));

            assertThat(registry.getAllRules(), is(empty()));
        }

        @Test
        void shouldUnregisterByTool() {
            GspmRule pscan1 = rule("pscan", 10020);
            GspmRule pscan2 = rule("pscan", 10021);
            GspmRule ascan1 = rule("ascan", 1);
            registry.registerRule(pscan1);
            registry.registerRule(pscan2);
            registry.registerRule(ascan1);

            registry.unregisterByTool("pscan");

            assertThat(registry.getAllRules(), contains(ascan1));
        }

        @Test
        void shouldBeNoOpWhenUnregisteringByToolWithNoRegisteredRules() {
            registry.registerRule(rule("ascan", 1));

            registry.unregisterByTool("pscan");

            assertThat(registry.getAllRules(), hasSize(1));
        }

        @Test
        void shouldRejectNullToolInUnregisterByTool() {
            assertThrows(NullPointerException.class, () -> registry.unregisterByTool(null));
        }

        @Test
        void shouldGetRulesByTool() {
            GspmRule pscan1 = rule("pscan", 10020);
            GspmRule pscan2 = rule("pscan", 10021);
            GspmRule ascan1 = rule("ascan", 1);
            registry.registerRule(pscan1);
            registry.registerRule(pscan2);
            registry.registerRule(ascan1);

            List<GspmRule> pscanRules = registry.getRulesByTool("pscan");

            assertThat(pscanRules, contains(pscan1, pscan2));
        }

        @Test
        void shouldReturnEmptyListForUnknownTool() {
            assertThat(registry.getRulesByTool("pscan"), is(empty()));
        }

        @Test
        void shouldRejectNullToolInGetRulesByTool() {
            assertThrows(NullPointerException.class, () -> registry.getRulesByTool(null));
        }

        @Test
        void shouldReportIsRegistered() {
            registry.registerRule(rule("pscan", 10020));

            assertThat(registry.isRegistered(10020), is(true));
            assertThat(registry.isRegistered(10021), is(false));
        }

        @Test
        void shouldReturnSnapshotFromGetAllRules() {
            registry.registerRule(rule("pscan", 10020));
            List<GspmRule> snapshot = registry.getAllRules();

            assertThat(snapshot.size(), is(1));
            assertThat(snapshot.get(0).getId(), is(10020));
        }

        @Test
        void shouldAllowSameRuleToBeReregisteredAfterUnregistration() {
            GspmRule rule = rule("pscan", 10020);
            registry.registerRule(rule);
            registry.unregisterRule(rule);

            registry.registerRule(rule);

            assertThat(registry.getAllRules(), contains(rule));
        }
    }

    @Nested
    class Listeners {

        @Test
        void shouldNotifyListenerOnRegister() {
            RecordingListener listener = new RecordingListener();
            registry.addListener(listener);
            GspmRule rule = rule("pscan", 10020);

            registry.registerRule(rule);

            assertThat(listener.registered, contains(rule));
            assertThat(listener.unregistered, is(empty()));
        }

        @Test
        void shouldNotifyListenerOnUnregister() {
            RecordingListener listener = new RecordingListener();
            GspmRule rule = rule("pscan", 10020);
            registry.registerRule(rule);
            registry.addListener(listener);

            registry.unregisterRule(rule);

            assertThat(listener.unregistered, contains(rule));
            assertThat(listener.registered, is(empty()));
        }

        @Test
        void shouldNotifyListenerOnUnregisterByTool() {
            GspmRule rule1 = rule("pscan", 10020);
            GspmRule rule2 = rule("pscan", 10021);
            registry.registerRule(rule1);
            registry.registerRule(rule2);
            RecordingListener listener = new RecordingListener();
            registry.addListener(listener);

            registry.unregisterByTool("pscan");

            assertThat(listener.unregistered, hasSize(2));
        }

        @Test
        void shouldNotNotifyRemovedListener() {
            RecordingListener listener = new RecordingListener();
            registry.addListener(listener);
            registry.removeListener(listener);

            registry.registerRule(rule("pscan", 10020));

            assertThat(listener.registered, is(empty()));
        }

        @Test
        void shouldRejectNullListener() {
            assertThrows(NullPointerException.class, () -> registry.addListener(null));
        }
    }

    @Nested
    class PolicyManagement {

        @Test
        void shouldAddAndRetrievePolicy() {
            GspmPolicy policy = new GspmPolicy("MyPolicy");

            registry.addPolicy(policy);

            assertThat(registry.getPolicy("MyPolicy"), is(policy));
        }

        @Test
        void shouldReturnNullForUnknownPolicy() {
            assertThat(registry.getPolicy("Unknown"), is(nullValue()));
        }

        @Test
        void shouldRemovePolicy() {
            registry.addPolicy(new GspmPolicy("MyPolicy"));

            registry.removePolicy("MyPolicy");

            assertThat(registry.getPolicy("MyPolicy"), is(nullValue()));
        }

        @Test
        void shouldClearCurrentPolicyWhenItIsRemoved() {
            registry.addPolicy(new GspmPolicy("MyPolicy"));
            registry.setCurrentPolicy("MyPolicy");

            registry.removePolicy("MyPolicy");

            assertThat(registry.getCurrentPolicy(), is(nullValue()));
        }

        @Test
        void shouldNotClearCurrentPolicyWhenADifferentPolicyIsRemoved() {
            registry.addPolicy(new GspmPolicy("PolicyA"));
            registry.addPolicy(new GspmPolicy("PolicyB"));
            registry.setCurrentPolicy("PolicyA");

            registry.removePolicy("PolicyB");

            assertThat(registry.getCurrentPolicy(), is("PolicyA"));
        }

        @Test
        void shouldGetAllPoliciesInInsertionOrder() {
            GspmPolicy a = new GspmPolicy("A");
            GspmPolicy b = new GspmPolicy("B");
            registry.addPolicy(a);
            registry.addPolicy(b);

            assertThat(registry.getAllPolicies(), contains(a, b));
        }

        @Test
        void shouldReplaceExistingPolicyWithSameName() {
            GspmPolicy original = new GspmPolicy("P");
            GspmPolicy replacement = new GspmPolicy("P");
            registry.addPolicy(original);

            registry.addPolicy(replacement);

            assertThat(registry.getPolicy("P"), is(replacement));
            assertThat(registry.getAllPolicies(), hasSize(1));
        }

        @Test
        void shouldDisambiguateFileNameCollisionWithADifferentlyNamedPolicy() {
            // Given — renaming "A" to "B" deliberately keeps its file name as "A"
            GspmPolicy a = new GspmPolicy("A");
            registry.addPolicy(a);
            registry.renamePolicy(a, "B");

            // When — a brand new policy named "A" defaults its file name to "A" too
            GspmPolicy newA = new GspmPolicy("A");
            registry.addPolicy(newA);

            // Then — the new policy is disambiguated so it doesn't collide with "B"'s file
            assertThat(newA.getFileName(), is(not("A")));
            assertThat(a.getFileName(), is("A"));
        }

        @Test
        void shouldDisambiguateFileNameCollisionCaseInsensitively() {
            // Given
            GspmPolicy original = new GspmPolicy("Original");
            original.setFileName("shared");
            registry.addPolicy(original);

            // When
            GspmPolicy other = new GspmPolicy("Other");
            other.setFileName("SHARED");
            registry.addPolicy(other);

            // Then
            assertThat(other.getFileName(), is(not("SHARED")));
        }

        @Test
        void shouldNotDisambiguateWhenReAddingTheSamePolicyName() {
            // Given
            GspmPolicy original = new GspmPolicy("P");
            original.setFileName("shared");
            registry.addPolicy(original);

            // When — re-adding under the same name (e.g. import replacing itself) shouldn't be
            // treated as a collision with the entry it's replacing
            GspmPolicy replacement = new GspmPolicy("P");
            replacement.setFileName("shared");
            registry.addPolicy(replacement);

            // Then
            assertThat(replacement.getFileName(), is("shared"));
        }

        @Test
        void shouldRejectNullPolicy() {
            assertThrows(NullPointerException.class, () -> registry.addPolicy(null));
        }
    }

    @Nested
    class RenamePolicy {

        @Test
        void shouldRenamePolicy() {
            GspmPolicy policy = new GspmPolicy("Old");
            registry.addPolicy(policy);

            registry.renamePolicy(policy, "New");

            assertThat(policy.getName(), is("New"));
            assertThat(registry.getPolicy("New"), is(policy));
            assertThat(registry.getPolicy("Old"), is(nullValue()));
        }

        @Test
        void shouldLockInFileNameOnRename() {
            GspmPolicy policy = new GspmPolicy("Old");
            registry.addPolicy(policy);

            registry.renamePolicy(policy, "New");

            assertThat(policy.getFileName(), is("Old"));
        }

        @Test
        void shouldBeNoOpWhenRenamingToSameName() {
            GspmPolicy policy = new GspmPolicy("Same");
            registry.addPolicy(policy);

            registry.renamePolicy(policy, "Same");

            assertThat(registry.getPolicy("Same"), is(policy));
        }

        @Test
        void shouldUpdateCurrentPolicyNameOnRename() {
            GspmPolicy policy = new GspmPolicy("Old");
            registry.addPolicy(policy);
            registry.setCurrentPolicy("Old");

            registry.renamePolicy(policy, "New");

            assertThat(registry.getCurrentPolicy(), is("New"));
        }

        @Test
        void shouldRejectRenameToNameOfAnotherExistingPolicy() {
            GspmPolicy policyA = new GspmPolicy("A");
            GspmPolicy policyB = new GspmPolicy("B");
            registry.addPolicy(policyA);
            registry.addPolicy(policyB);

            assertThrows(IllegalArgumentException.class, () -> registry.renamePolicy(policyA, "B"));
            assertThat(policyA.getName(), is("A"));
        }

        @Test
        void shouldRejectRenameOfUnregisteredPolicy() {
            GspmPolicy policy = new GspmPolicy("Unregistered");

            assertThrows(
                    IllegalArgumentException.class, () -> registry.renamePolicy(policy, "New"));
        }

        @Test
        void shouldRejectNullPolicyOnRename() {
            assertThrows(NullPointerException.class, () -> registry.renamePolicy(null, "New"));
        }

        @Test
        void shouldRejectNullNewNameOnRename() {
            GspmPolicy policy = new GspmPolicy("Old");
            registry.addPolicy(policy);

            assertThrows(NullPointerException.class, () -> registry.renamePolicy(policy, null));
        }
    }

    @Nested
    class CurrentPolicy {

        @Test
        void shouldStartWithNoCurrentPolicy() {
            assertThat(registry.getCurrentPolicy(), is(nullValue()));
        }

        @Test
        void shouldSetAndGetCurrentPolicy() {
            registry.addPolicy(new GspmPolicy("MyPolicy"));

            registry.setCurrentPolicy("MyPolicy");

            assertThat(registry.getCurrentPolicy(), is("MyPolicy"));
        }

        @Test
        void shouldClearCurrentPolicy() {
            registry.addPolicy(new GspmPolicy("MyPolicy"));
            registry.setCurrentPolicy("MyPolicy");

            registry.clearCurrentPolicy();

            assertThat(registry.getCurrentPolicy(), is(nullValue()));
        }

        @Test
        void shouldRejectSetCurrentPolicyForUnknownPolicy() {
            assertThrows(
                    IllegalArgumentException.class, () -> registry.setCurrentPolicy("Unknown"));
        }
    }

    @Nested
    class PolicyViews {

        @Test
        void shouldReturnRawRulesWhenNoCurrentPolicy() {
            GspmRule rule = rule("pscan", 10020);
            registry.registerRule(rule);

            List<GspmRule> result = registry.getRulesByTool("pscan");

            assertThat(result, contains(rule));
        }

        @Test
        void shouldApplyCurrentPolicyWhenSet() {
            GspmRule rule = rule("pscan", 10020);
            registry.registerRule(rule);
            GspmPolicy policy = new GspmPolicy("P");
            policy.setRuleThreshold(10020, "pscan-10020", AlertThreshold.OFF);
            registry.addPolicy(policy);
            registry.setCurrentPolicy("P");

            List<GspmRule> result = registry.getRulesByTool("pscan");

            assertThat(result.get(0).isEnabled(), is(false));
        }

        @Test
        void shouldApplyNamedPolicyWhenRequested() {
            GspmRule rule = activeRule("ascan", 1);
            registry.registerRule(rule);
            GspmPolicy policy = new GspmPolicy("Pentest");
            policy.setRuleThreshold(1, "ascan-1", AlertThreshold.LOW);
            registry.addPolicy(policy);

            List<GspmRule> result = registry.getRulesByTool("ascan", "Pentest");

            assertThat(result.get(0).getAlertThreshold(), is(AlertThreshold.LOW));
        }

        @Test
        void shouldThrowForUnknownNamedPolicy() {
            registry.registerRule(rule("pscan", 10020));

            assertThrows(
                    IllegalArgumentException.class,
                    () -> registry.getRulesByTool("pscan", "Unknown"));
        }

        @Test
        void shouldFallThroughToRuleValueWhenNoPerRuleOverride() {
            GspmRule rule = rule("pscan", 10020);
            registry.registerRule(rule);
            registry.addPolicy(new GspmPolicy("P"));
            registry.setCurrentPolicy("P");

            List<GspmRule> result = registry.getRulesByTool("pscan");

            assertThat(result.get(0).getAlertThreshold(), is(AlertThreshold.MEDIUM));
            assertThat(result.get(0).isEnabled(), is(true));
        }

        @Test
        void shouldApplyPolicyDefaultThresholdWhenNoPerRuleOverride() {
            GspmRule rule = rule("pscan", 10020);
            registry.registerRule(rule);
            GspmPolicy policy = new GspmPolicy("P");
            policy.setDefaultThreshold(AlertThreshold.HIGH);
            registry.addPolicy(policy);
            registry.setCurrentPolicy("P");

            List<GspmRule> result = registry.getRulesByTool("pscan");

            assertThat(result.get(0).getAlertThreshold(), is(AlertThreshold.HIGH));
        }

        @Test
        void shouldPreferPerRuleOverrideOverPolicyDefault() {
            GspmRule rule = rule("pscan", 10020);
            registry.registerRule(rule);
            GspmPolicy policy = new GspmPolicy("P");
            policy.setDefaultThreshold(AlertThreshold.HIGH);
            policy.setRuleThreshold(10020, "pscan-10020", AlertThreshold.LOW);
            registry.addPolicy(policy);
            registry.setCurrentPolicy("P");

            List<GspmRule> result = registry.getRulesByTool("pscan");

            assertThat(result.get(0).getAlertThreshold(), is(AlertThreshold.LOW));
        }

        @Test
        void shouldApplyStrengthOverrideForActiveRules() {
            GspmRule rule = activeRule("ascan", 1);
            registry.registerRule(rule);
            GspmPolicy policy = new GspmPolicy("P");
            policy.setRuleStrength(1, "ascan-1", AttackStrength.INSANE);
            registry.addPolicy(policy);
            registry.setCurrentPolicy("P");

            List<GspmRule> result = registry.getRulesByTool("ascan");

            assertThat(result.get(0).getAttackStrength(), is(AttackStrength.INSANE));
        }

        @Test
        void shouldReturnNullStrengthForPassiveRulesEvenWithPolicyDefault() {
            GspmRule rule = rule("pscan", 10020);
            registry.registerRule(rule);
            GspmPolicy policy = new GspmPolicy("P");
            policy.setDefaultStrength(AttackStrength.HIGH);
            registry.addPolicy(policy);
            registry.setCurrentPolicy("P");

            List<GspmRule> result = registry.getRulesByTool("pscan");

            assertThat(result.get(0).getAttackStrength(), is(nullValue()));
        }

        @Test
        void shouldWriteEnabledBackToPolicyViaView() {
            GspmRule rule = rule("pscan", 10020);
            registry.registerRule(rule);
            GspmPolicy policy = new GspmPolicy("P");
            registry.addPolicy(policy);
            registry.setCurrentPolicy("P");

            GspmRule view = registry.getRulesByTool("pscan").get(0);
            view.setEnabled(false);

            assertThat(view.getAlertThreshold(), is(AlertThreshold.OFF));
            assertThat(rule.isEnabled(), is(true));
        }

        @Test
        void shouldWriteThresholdBackToPolicyViaView() {
            GspmRule rule = rule("pscan", 10020);
            registry.registerRule(rule);
            GspmPolicy policy = new GspmPolicy("P");
            registry.addPolicy(policy);
            registry.setCurrentPolicy("P");

            GspmRule view = registry.getRulesByTool("pscan").get(0);
            view.setAlertThreshold(AlertThreshold.LOW);

            assertThat(view.getAlertThreshold(), is(AlertThreshold.LOW));
            assertThat(rule.getAlertThreshold(), is(AlertThreshold.MEDIUM));
        }

        @Test
        void shouldReEnableDisabledRuleInPolicy() {
            GspmRule rule = rule("pscan", 10020);
            registry.registerRule(rule);
            GspmPolicy policy = new GspmPolicy("P");
            registry.addPolicy(policy);
            registry.setCurrentPolicy("P");

            GspmRule view = registry.getRulesByTool("pscan").get(0);
            view.setEnabled(false);
            assertThat(view.isEnabled(), is(false));

            view.setEnabled(true);
            assertThat(view.isEnabled(), is(true));
        }

        @Test
        void shouldNotOverrideExistingNonOffThresholdWhenEnabling() {
            GspmRule rule = rule("pscan", 10020);
            registry.registerRule(rule);
            GspmPolicy policy = new GspmPolicy("P");
            registry.addPolicy(policy);
            registry.setCurrentPolicy("P");

            GspmRule view = registry.getRulesByTool("pscan").get(0);
            view.setAlertThreshold(AlertThreshold.LOW);
            view.setEnabled(true);

            assertThat(view.getAlertThreshold(), is(AlertThreshold.LOW));
        }

        @Test
        void shouldReEnableRuleDisabledByInheritedCatchAllThreshold() {
            GspmRule rule = rule("pscan", 10020);
            registry.registerRule(rule);
            GspmPolicy policy = new GspmPolicy("P");
            policy.setDefaultThreshold(AlertThreshold.OFF);
            registry.addPolicy(policy);
            registry.setCurrentPolicy("P");

            GspmRule view = registry.getRulesByTool("pscan").get(0);
            assertThat(view.isEnabled(), is(false));

            view.setEnabled(true);

            assertThat(view.isEnabled(), is(true));
            assertThat(view.getAlertThreshold(), is(not(AlertThreshold.OFF)));
        }

        @Test
        void shouldReEnableRuleDisabledByInheritedCategoryThreshold() {
            GspmRule rule = rule("pscan", 10020);
            registry.registerRule(rule);
            GspmPolicy policy = new GspmPolicy("P");
            policy.findOrCreateCategoryRuleSet("all.pscan").setThresholdEnum(AlertThreshold.OFF);
            registry.addPolicy(policy);
            registry.setCurrentPolicy("P");

            GspmRule view = registry.getRulesByTool("pscan").get(0);
            assertThat(view.isEnabled(), is(false));

            view.setEnabled(true);

            assertThat(view.isEnabled(), is(true));
            assertThat(view.getAlertThreshold(), is(not(AlertThreshold.OFF)));
        }

        @Test
        void shouldIgnoreStrengthSetterOnPassiveRuleView() {
            GspmRule rule = rule("pscan", 10020);
            registry.registerRule(rule);
            GspmPolicy policy = new GspmPolicy("P");
            registry.addPolicy(policy);
            registry.setCurrentPolicy("P");

            GspmRule view = registry.getRulesByTool("pscan").get(0);
            view.setAttackStrength(AttackStrength.HIGH);

            assertThat(view.getAttackStrength(), is(nullValue()));
            assertThat(policy.getEffectiveStrength(rule).isPresent(), is(false));
        }
    }

    @Nested
    class AllRulesForPolicy {

        @Test
        void shouldReturnViewsForAllRegisteredRulesAcrossTools() {
            // Given
            registry.registerRule(rule("pscan", 10020));
            registry.registerRule(activeRule("ascan", 1));
            GspmPolicy policy = new GspmPolicy("P");

            // When
            List<GspmRule> result = registry.getAllRulesForPolicy(policy);

            // Then
            assertThat(result, hasSize(2));
        }

        @Test
        void shouldApplyPolicyConfigurationToReturnedViews() {
            // Given
            GspmRule underlying = rule("pscan", 10020);
            registry.registerRule(underlying);
            GspmPolicy policy = new GspmPolicy("P");
            policy.setRuleThreshold(10020, "pscan-10020", AlertThreshold.HIGH);

            // When
            List<GspmRule> result = registry.getAllRulesForPolicy(policy);

            // Then
            assertThat(result.get(0).getAlertThreshold(), is(AlertThreshold.HIGH));
            assertThat(underlying.getAlertThreshold(), is(AlertThreshold.MEDIUM));
        }

        @Test
        void shouldReturnUnmodifiableList() {
            // Given
            registry.registerRule(rule("pscan", 10020));
            GspmPolicy policy = new GspmPolicy("P");
            List<GspmRule> result = registry.getAllRulesForPolicy(policy);

            // When / Then
            assertThrows(UnsupportedOperationException.class, () -> result.add(rule("ascan", 1)));
        }

        @Test
        void shouldThrowForNullPolicy() {
            // Given / When / Then
            assertThrows(NullPointerException.class, () -> registry.getAllRulesForPolicy(null));
        }
    }

    // -- helpers --

    /** Creates a passive-style rule (strength is null). */
    private static GspmRule rule(String tool, int id) {
        return new TestGspmRule(tool, id, false);
    }

    /** Creates an active-style rule (strength defaults to MEDIUM). */
    private static GspmRule activeRule(String tool, int id) {
        return new TestGspmRule(tool, id, true);
    }

    private static class TestGspmRule implements GspmRule {
        private final String tool;
        private final int id;
        private final boolean supportsStrength;
        private boolean enabled = true;
        private AlertThreshold threshold = AlertThreshold.MEDIUM;
        private AttackStrength strength;

        TestGspmRule(String tool, int id, boolean supportsStrength) {
            this.tool = tool;
            this.id = id;
            this.supportsStrength = supportsStrength;
            this.strength = supportsStrength ? AttackStrength.MEDIUM : null;
        }

        @Override
        public int getId() {
            return id;
        }

        @Override
        public String getName() {
            return tool + "-" + id;
        }

        @Override
        public String getTool() {
            return tool;
        }

        @Override
        public GspmPhase getPhase() {
            return GspmPhase.PASSIVE;
        }

        @Override
        public List<GspmCategory> getCategories() {
            return Collections.emptyList();
        }

        @Override
        public Map<String, String> getAlertTags() {
            return Collections.emptyMap();
        }

        @Override
        public boolean isEnabled() {
            return enabled;
        }

        @Override
        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        @Override
        public AlertThreshold getAlertThreshold() {
            return threshold;
        }

        @Override
        public void setAlertThreshold(AlertThreshold threshold) {
            this.threshold = threshold;
        }

        @Override
        public AttackStrength getAttackStrength() {
            return strength;
        }

        @Override
        public void setAttackStrength(AttackStrength strength) {
            if (supportsStrength) {
                this.strength = strength;
            }
        }
    }

    @Nested
    class LoadPolicies {

        private static final String LEGACY_POLICY_XML =
                """
                <configuration>
                  <policy>My Policy</policy>
                  <scanner>
                    <level>MEDIUM</level>
                    <strength>HIGH</strength>
                  </scanner>
                  <locked>false</locked>
                  <plugins/>
                </configuration>
                """;

        @Test
        void shouldMigrateLegacyPolicyIntoRegistry(@TempDir Path dir) throws Exception {
            // Given
            Files.writeString(dir.resolve("My Policy.policy"), LEGACY_POLICY_XML);

            // When
            registry.loadPolicies(dir.toFile());

            // Then
            GspmPolicy policy = registry.getPolicy("My Policy");
            assertThat(policy, is(notNullValue()));
            GspmRuleSet ascanRuleSet = policy.findOrCreateCategoryRuleSet("all.ascan");
            assertThat(ascanRuleSet.getThresholdEnum(), is(AlertThreshold.MEDIUM));
            assertThat(ascanRuleSet.getStrengthEnum(), is(AttackStrength.HIGH));
        }

        @Test
        void shouldWritePolicy2FileOnMigration(@TempDir Path dir) throws Exception {
            // Given
            Files.writeString(dir.resolve("My Policy.policy"), LEGACY_POLICY_XML);

            // When
            registry.loadPolicies(dir.toFile());

            // Then
            assertThat(new File(dir.toFile(), "My Policy.policy2").exists(), is(true));
        }

        @Test
        void shouldWritePolicy2UsingLegacyFileNameWhenNameContainsSlash(@TempDir Path dir)
                throws Exception {
            // Given — display name has '/', file name does not
            String xml =
                    """
                    <configuration>
                      <policy>Developer CI/CD</policy>
                      <scanner>
                        <level>MEDIUM</level>
                        <strength>HIGH</strength>
                      </scanner>
                      <locked>false</locked>
                      <plugins/>
                    </configuration>
                    """;
            Files.writeString(dir.resolve("Dev CICD.policy"), xml);

            // When
            registry.loadPolicies(dir.toFile());

            // Then
            GspmPolicy policy = registry.getPolicy("Developer CI/CD");
            assertThat(policy, is(notNullValue()));
            assertThat(policy.getFileName(), is("Dev CICD"));
            assertThat(new File(dir.toFile(), "Dev CICD.policy2").exists(), is(true));
            assertThat(new File(dir.toFile(), "Developer CI").isDirectory(), is(false));
        }

        @Test
        void shouldNotMigrateLegacyPolicyWhenPolicy2AlreadyExists(@TempDir Path dir)
                throws Exception {
            // Given
            GspmPolicy existing = new GspmPolicy("My Policy");
            existing.save(dir);
            Files.writeString(dir.resolve("My Policy.policy"), LEGACY_POLICY_XML);

            // When
            registry.loadPolicies(dir.toFile());

            // Then
            assertThat(registry.getPolicy("My Policy"), is(notNullValue()));
            // Only one policy loaded — the .policy2, not a second from migration
            assertThat(registry.getAllPolicies(), hasSize(2)); // My Policy + Default Policy
        }

        @Test
        void shouldSkipMigrationWhenLegacyNameCollidesWithDifferentlyNamedPolicy(@TempDir Path dir)
                throws Exception {
            // Given — an existing .policy2 already registered as "My Policy", stored under a
            // different file name so the base-file-name skip above doesn't catch this case.
            GspmPolicy existing = new GspmPolicy("My Policy");
            existing.setFileName("Existing File Name");
            existing.save(dir);
            // The legacy file's own base name differs, but its embedded <policy> name collides.
            Files.writeString(dir.resolve("Legacy File Name.policy"), LEGACY_POLICY_XML);

            // When
            registry.loadPolicies(dir.toFile());

            // Then — migration was skipped entirely; no second file was written for the collision
            assertThat(registry.getAllPolicies(), hasSize(2)); // My Policy + Default Policy
            assertThat(registry.getPolicy("My Policy").getFileName(), is("Existing File Name"));
            assertThat(new File(dir.toFile(), "Legacy File Name.policy2").exists(), is(false));
        }

        @Test
        void shouldCreateDefaultPolicyWhenNoneExists(@TempDir Path dir) throws Exception {
            // Given - empty directory

            // When
            registry.loadPolicies(dir.toFile());

            // Then
            GspmPolicy def = registry.getPolicy(GspmRegistry.getDefaultPolicyName());
            assertThat(def, is(notNullValue()));
            assertThat(def.getDefaultThreshold().get(), is(AlertThreshold.MEDIUM));
            assertThat(def.getDefaultStrength().get(), is(AttackStrength.MEDIUM));
            assertThat(
                    new File(dir.toFile(), GspmRegistry.getDefaultPolicyName() + ".policy2")
                            .exists(),
                    is(true));
        }

        @Test
        void shouldNotDuplicateDefaultPolicyWhenAlreadyLoaded(@TempDir Path dir) throws Exception {
            // Given
            GspmPolicy existing = new GspmPolicy(GspmRegistry.getDefaultPolicyName());
            existing.save(dir);

            // When
            registry.loadPolicies(dir.toFile());

            // Then
            assertThat(registry.getAllPolicies(), hasSize(1));
        }

        @Test
        void shouldMigrateLegacyLockedPolicyWithAscanThresholdOff(@TempDir Path dir)
                throws Exception {
            // Given
            String xml =
                    """
                    <configuration>
                      <policy>Locked Policy</policy>
                      <scanner><level>MEDIUM</level><strength>HIGH</strength></scanner>
                      <locked>true</locked>
                      <plugins/>
                    </configuration>
                    """;
            Files.writeString(dir.resolve("Locked Policy.policy"), xml);

            // When
            registry.loadPolicies(dir.toFile());

            // Then
            GspmRuleSet ascanRuleSet =
                    registry.getPolicy("Locked Policy").findOrCreateCategoryRuleSet("all.ascan");
            assertThat(ascanRuleSet.getThresholdEnum(), is(AlertThreshold.OFF));
            // strength still taken from <scanner><strength>
            assertThat(ascanRuleSet.getStrengthEnum(), is(AttackStrength.HIGH));
        }

        @Test
        void shouldMigrateLegacyPolicyWithPerRuleOverrides(@TempDir Path dir) throws Exception {
            // Given
            String xml =
                    """
                    <configuration>
                      <policy>Overrides</policy>
                      <scanner><level>MEDIUM</level><strength>MEDIUM</strength></scanner>
                      <locked>false</locked>
                      <plugins>
                        <p40012><enabled>false</enabled></p40012>
                        <p40014><level>HIGH</level><strength>INSANE</strength></p40014>
                      </plugins>
                    </configuration>
                    """;
            Files.writeString(dir.resolve("Overrides.policy"), xml);

            // When
            registry.loadPolicies(dir.toFile());

            // Then
            GspmPolicy policy = registry.getPolicy("Overrides");
            GspmRule disabledRule = rule("ascan", 40012);
            GspmRule highRule = rule("ascan", 40014);
            assertThat(policy.getEffectiveThreshold(disabledRule).get(), is(AlertThreshold.OFF));
            assertThat(policy.getEffectiveThreshold(highRule).get(), is(AlertThreshold.HIGH));
            assertThat(policy.getEffectiveStrength(highRule).get(), is(AttackStrength.INSANE));
        }
    }

    private static class RecordingListener implements RegistryListener {
        final List<GspmRule> registered = new ArrayList<>();
        final List<GspmRule> unregistered = new ArrayList<>();

        @Override
        public void ruleRegistered(GspmRule rule) {
            registered.add(rule);
        }

        @Override
        public void ruleUnregistered(GspmRule rule) {
            unregistered.add(rule);
        }
    }
}
