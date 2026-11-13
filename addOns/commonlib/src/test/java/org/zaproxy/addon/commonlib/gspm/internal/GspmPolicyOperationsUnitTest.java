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
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.zaproxy.addon.commonlib.ExtensionCommonlib;
import org.zaproxy.addon.commonlib.gspm.GspmCategory;
import org.zaproxy.addon.commonlib.gspm.GspmPhase;
import org.zaproxy.addon.commonlib.gspm.GspmPolicy;
import org.zaproxy.addon.commonlib.gspm.GspmRegistry;
import org.zaproxy.addon.commonlib.gspm.GspmRule;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit test for {@link GspmPolicyOperations}. */
class GspmPolicyOperationsUnitTest extends TestUtils {

    private static final int INJECTION_RULE = 100;
    private static final int INJECTION_RULE_2 = 101;
    private static final int SERVER_RULE = 200;

    @TempDir static java.nio.file.Path policiesDir;

    private static String zapHome;

    @BeforeAll
    static void setup() {
        mockMessages(new ExtensionCommonlib());
        zapHome = Constant.getZapHome();
        Constant.setZapHome(policiesDir.toString());
    }

    @AfterAll
    static void cleanUp() {
        Constant.messages = null;
        if (zapHome != null) {
            Constant.setZapHome(zapHome);
        }
    }

    private GspmRegistry registry;

    @BeforeEach
    void setUp() throws Exception {
        java.nio.file.Files.createDirectories(Constant.getPoliciesDir().toPath());
        registry = new GspmRegistry();
        registry.registerRule(rule(INJECTION_RULE, Category.INJECTION));
        registry.registerRule(rule(INJECTION_RULE_2, Category.INJECTION));
        registry.registerRule(rule(SERVER_RULE, Category.SERVER));
    }

    @Test
    void shouldAddPolicyWithDefaults() {
        // When
        GspmPolicyOperations.addPolicy(registry, "New", "ascan", AlertThreshold.HIGH, null);
        // Then
        GspmPolicy policy = registry.getPolicy("New");
        assertThat(threshold("New", INJECTION_RULE), is(AlertThreshold.HIGH));
        assertThat(strength("New", INJECTION_RULE), is(AttackStrength.MEDIUM));
        assertThat(policy.getFile().exists(), is(true));
    }

    @Test
    void shouldNotAddExistingOrIllegalPolicy() {
        // Given
        GspmPolicyOperations.addPolicy(registry, "New", "ascan", null, null);
        // When / Then
        assertThrows(
                IllegalStateException.class,
                () -> GspmPolicyOperations.addPolicy(registry, "New", "ascan", null, null));
        assertThrows(
                IllegalArgumentException.class,
                () -> GspmPolicyOperations.addPolicy(registry, "a/b", "ascan", null, null));
    }

    @Test
    void shouldUpdateOnlyGivenDefaults() {
        // Given
        GspmPolicyOperations.addPolicy(
                registry, "P", "ascan", AlertThreshold.LOW, AttackStrength.HIGH);
        // When
        GspmPolicyOperations.updatePolicy(registry, "P", "ascan", null, AttackStrength.LOW);
        // Then
        assertThat(threshold("P", SERVER_RULE), is(AlertThreshold.LOW));
        assertThat(strength("P", SERVER_RULE), is(AttackStrength.LOW));
    }

    @Test
    void shouldRemovePolicyAndFile() {
        // Given
        GspmPolicyOperations.addPolicy(registry, "P", "ascan", null, null);
        java.io.File file = registry.getPolicy("P").getFile();
        // When
        GspmPolicyOperations.removePolicy(registry, "P");
        // Then
        assertThat(registry.getPolicy("P") == null, is(true));
        assertThat(file.exists(), is(false));
    }

    @Test
    void shouldRemoveLegacyFileOfMigratedPolicy() throws Exception {
        // Given
        java.io.File legacyFile = new java.io.File(Constant.getPoliciesDir(), "Migrated.policy");
        java.nio.file.Files.writeString(legacyFile.toPath(), "<root/>");
        GspmPolicy policy = new GspmPolicy("Migrated");
        registry.addPolicy(policy);
        policy.save();
        java.io.File file = policy.getFile();
        // When
        GspmPolicyOperations.removePolicy(registry, "Migrated");
        // Then
        assertThat(file.exists(), is(false));
        assertThat(legacyFile.exists(), is(false));
    }

    /** A policy as migrated from a legacy one, the rules with the same settings share them. */
    private void addMigratedPolicy(String name) {
        GspmPolicy policy = new GspmPolicy(name);
        policy.findOrCreateCategoryRuleSet("all.ascan").setThresholdEnum(AlertThreshold.LOW);
        policy.findOrCreateCategoryRuleSet("all.ascan").setStrengthEnum(AttackStrength.MEDIUM);
        org.zaproxy.addon.commonlib.gspm.GspmRuleSet off =
                new org.zaproxy.addon.commonlib.gspm.GspmRuleSet();
        off.addRule(new org.zaproxy.addon.commonlib.gspm.GspmRuleRef(INJECTION_RULE, "r"));
        off.addRule(new org.zaproxy.addon.commonlib.gspm.GspmRuleRef(INJECTION_RULE_2, "r"));
        off.addRule(new org.zaproxy.addon.commonlib.gspm.GspmRuleRef(SERVER_RULE, "r"));
        off.setThresholdEnum(AlertThreshold.OFF);
        policy.getRuleSets().add(off);
        registry.addPolicy(policy);
    }

    @Test
    void shouldSetCategoryThresholdOfRulesSharingOverrides() {
        // Given
        addMigratedPolicy("M");
        // When
        GspmPolicyOperations.setCategoryThreshold(
                registry, "M", "ascan", "inject", AlertThreshold.HIGH);
        // Then
        assertThat(threshold("M", INJECTION_RULE), is(AlertThreshold.HIGH));
        assertThat(threshold("M", INJECTION_RULE_2), is(AlertThreshold.HIGH));
        assertThat(threshold("M", SERVER_RULE), is(AlertThreshold.OFF));
    }

    @Test
    void shouldSetCategoryStrengthOfRulesSharingOverrides() {
        // Given
        addMigratedPolicy("M");
        registry.getPolicy("M").getRuleSets().get(1).setStrengthEnum(AttackStrength.LOW);
        // When
        GspmPolicyOperations.setCategoryStrength(
                registry, "M", "ascan", "inject", AttackStrength.INSANE);
        // Then
        assertThat(strength("M", INJECTION_RULE), is(AttackStrength.INSANE));
        assertThat(strength("M", SERVER_RULE), is(AttackStrength.LOW));
        assertThat(threshold("M", INJECTION_RULE), is(AlertThreshold.OFF));
    }

    @Test
    void shouldClearThresholdOfRuleSharingOverrideWithDefault() {
        // Given
        addMigratedPolicy("M");
        // When
        GspmPolicyOperations.setRuleThreshold(
                registry, "M", "ascan", SERVER_RULE, AlertThreshold.DEFAULT);
        // Then
        assertThat(threshold("M", SERVER_RULE), is(AlertThreshold.LOW));
        assertThat(threshold("M", INJECTION_RULE), is(AlertThreshold.OFF));
    }

    @Test
    void shouldSetThresholdOfRuleSharingOverride() {
        // Given
        addMigratedPolicy("M");
        // When
        GspmPolicyOperations.setRuleThreshold(
                registry, "M", "ascan", SERVER_RULE, AlertThreshold.HIGH);
        // Then
        assertThat(threshold("M", SERVER_RULE), is(AlertThreshold.HIGH));
        assertThat(threshold("M", INJECTION_RULE), is(AlertThreshold.OFF));
    }

    @Test
    void shouldEnableRuleSharingOverrideWithoutAffectingOthers() {
        // Given
        addMigratedPolicy("M");
        // When
        GspmPolicyOperations.setRulesEnabled(registry, "M", "ascan", List.of(SERVER_RULE), true);
        // Then
        assertThat(threshold("M", SERVER_RULE), is(AlertThreshold.LOW));
        assertThat(threshold("M", INJECTION_RULE), is(AlertThreshold.OFF));
    }

    @Test
    void shouldKeepThresholdsOfRulesOfEnabledCategories() {
        // Given
        GspmPolicyOperations.addPolicy(
                registry, "C", "ascan", AlertThreshold.LOW, AttackStrength.MEDIUM);
        GspmPolicyOperations.setRuleThreshold(
                registry, "C", "ascan", SERVER_RULE, AlertThreshold.HIGH);
        GspmPolicyOperations.setRuleThreshold(
                registry, "C", "ascan", INJECTION_RULE, AlertThreshold.HIGH);
        // When
        GspmPolicyOperations.setEnabledCategories(registry, "C", "ascan", List.of("server"));
        // Then
        assertThat(threshold("C", SERVER_RULE), is(AlertThreshold.HIGH));
        assertThat(threshold("C", INJECTION_RULE), is(AlertThreshold.OFF));
        assertThat(threshold("C", INJECTION_RULE_2), is(AlertThreshold.OFF));
    }

    @Test
    void shouldNotSetStrengthOfRulesWithoutStrength() {
        // Given
        GspmRule noStrengthRule = new TestRule(300, "pscan", GspmPhase.PASSIVE, null, null);
        registry.registerRule(noStrengthRule);
        GspmPolicyOperations.addPolicy(registry, "S", null, null, null);
        // When
        GspmPolicyOperations.setRuleStrength(registry, "S", "pscan", 300, AttackStrength.HIGH);
        // Then
        assertThat(registry.getPolicy("S").getRuleSets().size(), is(1));
    }

    @Test
    void shouldKeepPolicyRegisteredIfItsFileCanNotBeDeleted() throws Exception {
        // Given
        GspmPolicyOperations.addPolicy(registry, "D", "ascan", null, null);
        java.io.File file = registry.getPolicy("D").getFile();
        // A directory with content, which can not be deleted as a file.
        assertThat(file.delete(), is(true));
        assertThat(file.mkdir(), is(true));
        java.nio.file.Files.writeString(new java.io.File(file, "content").toPath(), "x");
        // When
        assertThrows(
                java.io.UncheckedIOException.class,
                () -> GspmPolicyOperations.removePolicy(registry, "D"));
        // Then
        assertThat(registry.getPolicy("D") != null, is(true));
    }

    @Test
    void shouldKeepPolicyRegisteredIfItsLegacyFileCanNotBeDeletedAndAllowToRetry()
            throws Exception {
        // Given
        GspmPolicyOperations.addPolicy(registry, "L", "ascan", null, null);
        java.io.File legacy = new java.io.File(Constant.getPoliciesDir(), "L.policy");
        assertThat(legacy.mkdir(), is(true));
        java.io.File content = new java.io.File(legacy, "content");
        java.nio.file.Files.writeString(content.toPath(), "x");
        // When
        assertThrows(
                java.io.UncheckedIOException.class,
                () -> GspmPolicyOperations.removePolicy(registry, "L"));
        // Then
        assertThat(registry.getPolicy("L") != null, is(true));
        // When
        assertThat(content.delete(), is(true));
        assertThat(legacy.delete(), is(true));
        GspmPolicyOperations.removePolicy(registry, "L");
        // Then
        assertThat(registry.getPolicy("L") == null, is(true));
    }

    @Test
    void shouldIncludeDescendantCategoriesOfParentCategory() {
        // Given
        GspmRegistry hierarchy = new GspmRegistry();
        hierarchy.registerRule(
                new TestRule(1, "t", GspmPhase.ACTIVE, "a.b", AttackStrength.MEDIUM));
        hierarchy.registerRule(new TestRule(2, "t", GspmPhase.ACTIVE, "a", AttackStrength.MEDIUM));
        hierarchy.registerRule(new TestRule(3, "t", GspmPhase.ACTIVE, "ab", AttackStrength.MEDIUM));
        hierarchy.registerRule(new TestRule(4, "t", GspmPhase.ACTIVE, "c", AttackStrength.MEDIUM));
        GspmPolicyOperations.addPolicy(hierarchy, "H", "t", AlertThreshold.LOW, null);
        GspmPolicyOperations.setRuleThreshold(hierarchy, "H", "t", 1, AlertThreshold.HIGH);
        GspmPolicyOperations.setRuleThreshold(hierarchy, "H", "t", 3, AlertThreshold.HIGH);
        // When
        GspmPolicyOperations.setCategoryThreshold(hierarchy, "H", "t", "a", AlertThreshold.MEDIUM);
        // Then
        assertThat(thresholdOf(hierarchy, "H", 1), is(AlertThreshold.MEDIUM));
        assertThat(thresholdOf(hierarchy, "H", 2), is(AlertThreshold.MEDIUM));
        // Not a descendant, just a similar key.
        assertThat(thresholdOf(hierarchy, "H", 3), is(AlertThreshold.HIGH));
        assertThat(thresholdOf(hierarchy, "H", 4), is(AlertThreshold.LOW));
        // When
        GspmPolicyOperations.setEnabledCategories(hierarchy, "H", "t", List.of("a"));
        // Then
        assertThat(thresholdOf(hierarchy, "H", 1), is(AlertThreshold.MEDIUM));
        assertThat(thresholdOf(hierarchy, "H", 2), is(AlertThreshold.MEDIUM));
        assertThat(thresholdOf(hierarchy, "H", 3), is(AlertThreshold.OFF));
        assertThat(thresholdOf(hierarchy, "H", 4), is(AlertThreshold.OFF));
    }

    private static AlertThreshold thresholdOf(GspmRegistry registry, String policy, int ruleId) {
        return registry.getRulesByTool("t", policy).stream()
                .filter(r -> r.getId() == ruleId)
                .findFirst()
                .get()
                .getAlertThreshold();
    }

    @Test
    void shouldRemoveTheLegacyFileThePolicyWasMigratedFrom() throws Exception {
        // Given
        java.io.File legacy = new java.io.File(Constant.getPoliciesDir(), "Foo.policy");
        java.nio.file.Files.writeString(legacy.toPath(), "<root/>");
        java.io.File sameNameAsPolicyFile =
                new java.io.File(Constant.getPoliciesDir(), "Foo (2).policy");
        java.nio.file.Files.writeString(sameNameAsPolicyFile.toPath(), "<root/>");
        java.io.File other = new java.io.File(Constant.getPoliciesDir(), "Other.policy");
        java.nio.file.Files.writeString(other.toPath(), "<root/>");
        GspmPolicy policy = new GspmPolicy("Migrated");
        // As when another policy has the same file name.
        policy.setFileName("Foo (2)");
        policy.setLegacyFile(legacy);
        registry.addPolicy(policy);
        policy.save();
        // When
        GspmPolicyOperations.removePolicy(registry, "Migrated");
        // Then
        assertThat(legacy.exists(), is(false));
        assertThat(sameNameAsPolicyFile.exists(), is(false));
        assertThat(other.exists(), is(true));
        assertThat(registry.getPolicy("Migrated") == null, is(true));
    }

    @Test
    void shouldNotKeepAddedPolicyIfItCanNotBeSaved() throws Exception {
        // Given
        java.io.File blocker = blockPolicyFile("F");
        // When
        assertThrows(
                java.io.UncheckedIOException.class,
                () -> GspmPolicyOperations.addPolicy(registry, "F", "ascan", null, null));
        // Then
        assertThat(registry.getPolicy("F") == null, is(true));
        // When
        unblock(blocker);
        GspmPolicyOperations.addPolicy(registry, "F", "ascan", null, null);
        // Then
        assertThat(registry.getPolicy("F") != null, is(true));
    }

    @Test
    void shouldNotKeepImportedPolicyIfItCanNotBeSaved() throws Exception {
        // Given
        java.io.File file = java.nio.file.Files.createTempFile("Imported", ".policy").toFile();
        file.deleteOnExit();
        java.nio.file.Files.writeString(
                file.toPath(),
                "<configuration><policy>Imported</policy><scanner><level>HIGH</level>"
                        + "<strength>LOW</strength></scanner></configuration>");
        String baseName = file.getName().substring(0, file.getName().length() - ".policy".length());
        java.io.File blocker = blockPolicyFile(baseName);
        // When
        assertThrows(
                java.io.UncheckedIOException.class,
                () -> GspmPolicyOperations.importPolicy(registry, file));
        // Then
        assertThat(registry.getPolicy("Imported") == null, is(true));
        // When
        unblock(blocker);
        GspmPolicyOperations.importPolicy(registry, file);
        // Then
        assertThat(registry.getPolicy("Imported") != null, is(true));
    }

    /** Creates a directory with content where the file of the policy would be saved. */
    private static java.io.File blockPolicyFile(String fileName) throws Exception {
        java.io.File blocker = new java.io.File(Constant.getPoliciesDir(), fileName + ".policy2");
        assertThat(blocker.mkdir(), is(true));
        java.nio.file.Files.writeString(new java.io.File(blocker, "content").toPath(), "x");
        return blocker;
    }

    private static void unblock(java.io.File blocker) throws Exception {
        java.nio.file.Files.delete(new java.io.File(blocker, "content").toPath());
        java.nio.file.Files.delete(blocker.toPath());
    }

    @Test
    void shouldNotRemoveBuiltInPolicy() {
        // Given
        String builtIn = GspmRegistry.getDefaultPolicyName();
        registry.addPolicy(new GspmPolicy(builtIn));
        // When / Then
        assertThrows(
                IllegalArgumentException.class,
                () -> GspmPolicyOperations.removePolicy(registry, builtIn));
        assertThat(registry.getPolicy(builtIn) != null, is(true));
    }

    @Test
    void shouldFailToChangeUnknownPolicyOrRule() {
        assertThrows(
                IllegalArgumentException.class,
                () -> GspmPolicyOperations.removePolicy(registry, "Unknown"));
        GspmPolicyOperations.addPolicy(registry, "P", "ascan", null, null);
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        GspmPolicyOperations.setRuleThreshold(
                                registry, "P", "ascan", 999, AlertThreshold.LOW));
    }

    @Test
    void shouldSetAndClearRuleThresholdAndStrength() {
        // Given
        GspmPolicyOperations.addPolicy(
                registry, "P", "ascan", AlertThreshold.MEDIUM, AttackStrength.MEDIUM);
        // When
        GspmPolicyOperations.setRuleThreshold(
                registry, "P", "ascan", SERVER_RULE, AlertThreshold.HIGH);
        GspmPolicyOperations.setRuleStrength(
                registry, "P", "ascan", SERVER_RULE, AttackStrength.INSANE);
        // Then
        assertThat(threshold("P", SERVER_RULE), is(AlertThreshold.HIGH));
        assertThat(strength("P", SERVER_RULE), is(AttackStrength.INSANE));
        assertThat(threshold("P", INJECTION_RULE), is(AlertThreshold.MEDIUM));
        // When
        GspmPolicyOperations.setRuleThreshold(
                registry, "P", "ascan", SERVER_RULE, AlertThreshold.DEFAULT);
        GspmPolicyOperations.setRuleStrength(
                registry, "P", "ascan", SERVER_RULE, AttackStrength.DEFAULT);
        // Then
        assertThat(threshold("P", SERVER_RULE), is(AlertThreshold.MEDIUM));
        assertThat(strength("P", SERVER_RULE), is(AttackStrength.MEDIUM));
    }

    @Test
    void shouldDisableAndEnableAllRulesOfTheToolOnly() {
        // Given
        GspmPolicyOperations.addPolicy(
                registry, "P", "ascan", AlertThreshold.LOW, AttackStrength.MEDIUM);
        registry.registerRule(otherToolRule(300));
        GspmPolicy policy = registry.getPolicy("P");
        policy.setDefaultThreshold(AlertThreshold.HIGH);
        // When
        GspmPolicyOperations.setAllRulesEnabled(registry, "P", "ascan", false);
        // Then
        assertThat(threshold("P", INJECTION_RULE), is(AlertThreshold.OFF));
        assertThat(threshold("P", SERVER_RULE), is(AlertThreshold.OFF));
        assertThat(
                registry.getAllRulesForPolicy(policy).stream()
                        .filter(r -> r.getId() == 300)
                        .findFirst()
                        .get()
                        .isEnabled(),
                is(true));
        // When
        GspmPolicyOperations.setAllRulesEnabled(registry, "P", "ascan", true);
        // Then
        assertThat(threshold("P", INJECTION_RULE), is(AlertThreshold.LOW));
        assertThat(threshold("P", SERVER_RULE), is(AlertThreshold.LOW));
    }

    @Test
    void shouldDisableAndEnableGivenRules() {
        // Given
        GspmPolicyOperations.addPolicy(
                registry, "P", "ascan", AlertThreshold.LOW, AttackStrength.MEDIUM);
        // When
        GspmPolicyOperations.setRulesEnabled(
                registry, "P", "ascan", List.of(INJECTION_RULE, SERVER_RULE), false);
        GspmPolicyOperations.setRulesEnabled(registry, "P", "ascan", List.of(SERVER_RULE), true);
        // Then
        assertThat(threshold("P", INJECTION_RULE), is(AlertThreshold.OFF));
        assertThat(threshold("P", INJECTION_RULE_2), is(AlertThreshold.LOW));
        assertThat(threshold("P", SERVER_RULE), is(AlertThreshold.LOW));
    }

    @Test
    void shouldSetCategoryThresholdOverridingRuleOverrides() {
        // Given
        GspmPolicyOperations.addPolicy(
                registry, "P", "ascan", AlertThreshold.MEDIUM, AttackStrength.MEDIUM);
        GspmPolicyOperations.setRuleThreshold(
                registry, "P", "ascan", INJECTION_RULE, AlertThreshold.OFF);
        // When
        GspmPolicyOperations.setCategoryThreshold(
                registry, "P", "ascan", "inject", AlertThreshold.HIGH);
        GspmPolicyOperations.setCategoryStrength(
                registry, "P", "ascan", "inject", AttackStrength.INSANE);
        // Then
        assertThat(threshold("P", INJECTION_RULE), is(AlertThreshold.HIGH));
        assertThat(threshold("P", INJECTION_RULE_2), is(AlertThreshold.HIGH));
        assertThat(strength("P", INJECTION_RULE), is(AttackStrength.INSANE));
        assertThat(threshold("P", SERVER_RULE), is(AlertThreshold.MEDIUM));
    }

    @Test
    void shouldEnableOnlyGivenCategories() {
        // Given
        GspmPolicyOperations.addPolicy(
                registry, "P", "ascan", AlertThreshold.LOW, AttackStrength.MEDIUM);
        // When
        GspmPolicyOperations.setEnabledCategories(registry, "P", "ascan", List.of("server"));
        // Then
        assertThat(threshold("P", SERVER_RULE), is(AlertThreshold.LOW));
        assertThat(threshold("P", INJECTION_RULE), is(AlertThreshold.OFF));
        assertThat(threshold("P", INJECTION_RULE_2), is(AlertThreshold.OFF));
    }

    @Test
    void shouldGetDefaultThresholdAndStrength() {
        // Given
        GspmPolicyOperations.addPolicy(
                registry, "P", "ascan", AlertThreshold.HIGH, AttackStrength.LOW);
        registry.addPolicy(new GspmPolicy("Empty"));
        // When / Then
        assertThat(
                GspmPolicyOperations.getDefaultThreshold(registry, "P", "ascan"),
                is(AlertThreshold.HIGH));
        assertThat(
                GspmPolicyOperations.getDefaultStrength(registry, "P", "ascan"),
                is(AttackStrength.LOW));
        assertThat(
                GspmPolicyOperations.getDefaultThreshold(registry, "Empty", "ascan") == null,
                is(true));
    }

    private AlertThreshold threshold(String policy, int ruleId) {
        return rule(policy, ruleId).getAlertThreshold();
    }

    private AttackStrength strength(String policy, int ruleId) {
        return rule(policy, ruleId).getAttackStrength();
    }

    private GspmRule rule(String policy, int ruleId) {
        return registry.getAllRulesForPolicy(registry.getPolicy(policy)).stream()
                .filter(r -> r.getId() == ruleId)
                .findFirst()
                .get();
    }

    private static GspmRule rule(int id, int category) {
        return new TestRule(
                id, "ascan", GspmPhase.ACTIVE, categoryKey(category), AttackStrength.MEDIUM);
    }

    private static GspmRule otherToolRule(int id) {
        return new TestRule(id, "pscan", GspmPhase.PASSIVE, null, null);
    }

    private static String categoryKey(int category) {
        return GspmActiveScanRegistrar.categoryKey(category);
    }

    private static final class TestRule implements GspmRule {

        private final int id;
        private final String tool;
        private final GspmPhase phase;
        private final String category;
        private AttackStrength strength;
        private AlertThreshold threshold = AlertThreshold.MEDIUM;

        TestRule(int id, String tool, GspmPhase phase, String category, AttackStrength strength) {
            this.id = id;
            this.tool = tool;
            this.phase = phase;
            this.category = category;
            this.strength = strength;
        }

        @Override
        public int getId() {
            return id;
        }

        @Override
        public String getName() {
            return "Rule " + id;
        }

        @Override
        public String getTool() {
            return tool;
        }

        @Override
        public GspmPhase getPhase() {
            return phase;
        }

        @Override
        public List<GspmCategory> getCategories() {
            return category == null ? List.of() : List.of(new GspmCategory(category, category));
        }

        @Override
        public Map<String, String> getAlertTags() {
            return Map.of();
        }

        @Override
        public boolean isEnabled() {
            return threshold != AlertThreshold.OFF;
        }

        @Override
        public void setEnabled(boolean enabled) {}

        @Override
        public AlertThreshold getAlertThreshold() {
            return threshold;
        }

        @Override
        public void setAlertThreshold(AlertThreshold threshold) {}

        @Override
        public AttackStrength getAttackStrength() {
            return strength;
        }

        @Override
        public void setAttackStrength(AttackStrength strength) {}
    }
}
