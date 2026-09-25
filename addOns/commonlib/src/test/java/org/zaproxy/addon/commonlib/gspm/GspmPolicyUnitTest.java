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
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.sameInstance;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.File;
import java.lang.reflect.Field;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.zaproxy.addon.commonlib.ExtensionCommonlib;
import org.zaproxy.zap.testutils.TestUtils;

@SuppressWarnings("OptionalGetWithoutIsPresent")
class GspmPolicyUnitTest extends TestUtils {

    @BeforeAll
    static void setupMessages() {
        // GspmPolicy.nextDefaultRuleSetName() reads Constant.messages.
        mockMessages(new ExtensionCommonlib());
    }

    @AfterAll
    static void cleanUpMessages() {
        Constant.messages = null;
    }

    @Test
    void shouldCreatePolicyWithName() {
        GspmPolicy policy = new GspmPolicy("Pentest");

        assertThat(policy.getName(), is("Pentest"));
    }

    @Test
    void shouldRejectNullName() {
        assertThrows(NullPointerException.class, () -> new GspmPolicy(null));
    }

    @Test
    void shouldRejectBlankName() {
        assertThrows(IllegalArgumentException.class, () -> new GspmPolicy("  "));
    }

    @Test
    void shouldAllowNameWithFileUnsafeChars() {
        GspmPolicy policy = new GspmPolicy("Developer CI/CD");

        assertThat(policy.getName(), is("Developer CI/CD"));
    }

    @Test
    void shouldSetName() {
        GspmPolicy policy = new GspmPolicy("Old");

        policy.setName("New");

        assertThat(policy.getName(), is("New"));
    }

    @Test
    void shouldRejectNullNameOnSet() {
        GspmPolicy policy = new GspmPolicy("Old");

        assertThrows(NullPointerException.class, () -> policy.setName(null));
    }

    @Test
    void shouldRejectBlankNameOnSet() {
        GspmPolicy policy = new GspmPolicy("Old");

        assertThrows(IllegalArgumentException.class, () -> policy.setName("  "));
    }

    @Test
    void shouldAcceptLegalName() {
        assertThat(GspmPolicy.isLegalPolicyName("My Policy 1"), is(true));
    }

    @Test
    void shouldFlagNameWithIllegalChars() {
        for (char c : GspmPolicy.ILLEGAL_POLICY_NAME_CHRS.toCharArray()) {
            assertThat(GspmPolicy.isLegalPolicyName("Policy" + c), is(false));
        }
    }

    @Test
    void shouldStartWithNoDefaults() {
        GspmPolicy policy = new GspmPolicy("P");

        assertThat(policy.getDefaultThreshold().isPresent(), is(false));
        assertThat(policy.getDefaultStrength().isPresent(), is(false));
    }

    @Test
    void shouldSetAndGetDefaultThreshold() {
        GspmPolicy policy = new GspmPolicy("P");

        policy.setDefaultThreshold(AlertThreshold.HIGH);

        assertThat(policy.getDefaultThreshold().get(), is(AlertThreshold.HIGH));
    }

    @Test
    void shouldClearDefaultThreshold() {
        GspmPolicy policy = new GspmPolicy("P");
        policy.setDefaultThreshold(AlertThreshold.HIGH);

        policy.setDefaultThreshold(null);

        assertThat(policy.getDefaultThreshold().isPresent(), is(false));
    }

    @Test
    void shouldSetAndGetDefaultStrength() {
        GspmPolicy policy = new GspmPolicy("P");

        policy.setDefaultStrength(AttackStrength.INSANE);

        assertThat(policy.getDefaultStrength().get(), is(AttackStrength.INSANE));
    }

    @Test
    void shouldStartWithEmptyRuleSets() {
        assertThat(new GspmPolicy("P").getRuleSets(), is(empty()));
    }

    @Test
    void shouldAddRuleSet() {
        GspmPolicy policy = new GspmPolicy("P");
        GspmRuleSet rs = new GspmRuleSet();
        rs.setThresholdEnum(AlertThreshold.HIGH);
        policy.getRuleSets().add(rs);
        assertThat(policy.getRuleSets(), hasSize(1));
    }

    @Test
    void shouldReturnFirstDefaultRuleSetNameWhenNoneUsedYet() {
        GspmPolicy policy = new GspmPolicy("P");
        assertThat(policy.nextDefaultRuleSetName(), is("Rule Set 1"));
    }

    @Test
    void shouldAutoIncrementDefaultRuleSetNameFromExistingOnes() {
        GspmPolicy policy = new GspmPolicy("P");
        GspmRuleSet rs1 = new GspmRuleSet();
        rs1.setName("Rule Set 1");
        policy.addRuleSet(rs1);
        GspmRuleSet rs2 = new GspmRuleSet();
        rs2.setName("Rule Set 2");
        policy.addRuleSet(rs2);

        assertThat(policy.nextDefaultRuleSetName(), is("Rule Set 3"));
    }

    @Test
    void shouldIgnoreUnrelatedOrModifiedNamesWhenComputingNextDefaultName() {
        GspmPolicy policy = new GspmPolicy("P");
        GspmRuleSet unrelated = new GspmRuleSet();
        unrelated.setName("My custom rule set");
        policy.addRuleSet(unrelated);
        GspmRuleSet modified = new GspmRuleSet();
        modified.setName("Rule Set 5 (copy)");
        policy.addRuleSet(modified);

        assertThat(policy.nextDefaultRuleSetName(), is("Rule Set 1"));
    }

    @Test
    void shouldNotFillGapsWhenComputingNextDefaultName() {
        GspmPolicy policy = new GspmPolicy("P");
        GspmRuleSet rs = new GspmRuleSet();
        rs.setName("Rule Set 5");
        policy.addRuleSet(rs);

        assertThat(policy.nextDefaultRuleSetName(), is("Rule Set 6"));
    }

    @Test
    void shouldReturnNullCatchAllRuleSetWhenNoneExists() {
        GspmPolicy policy = new GspmPolicy("P");
        assertThat(policy.findCatchAllRuleSet(), is(nullValue()));
    }

    @Test
    void shouldFindTheExistingCatchAllRuleSet() {
        GspmPolicy policy = new GspmPolicy("P");
        policy.setDefaultThreshold(AlertThreshold.HIGH);
        GspmRuleSet catchAll = policy.getRuleSets().get(0);
        assertThat(policy.findCatchAllRuleSet(), sameInstance(catchAll));
        assertThat(policy.getRuleSets(), hasSize(1));
    }

    @Test
    void shouldAssignDefaultNamesOnlyToAmbiguousRuleSets() {
        // Given
        GspmPolicy policy = new GspmPolicy("P");
        GspmRuleSet catchAll = new GspmRuleSet();
        policy.addRuleSet(catchAll);
        GspmRuleSet category = new GspmRuleSet();
        category.setCategory("all.ascan");
        policy.addRuleSet(category);
        GspmRuleSet tagOnly = new GspmRuleSet();
        tagOnly.setTags(List.of("FOO"));
        policy.addRuleSet(tagOnly);
        GspmRuleSet multiRule = new GspmRuleSet();
        multiRule.addRule(new GspmRuleRef(1, "Rule 1"));
        multiRule.addRule(new GspmRuleRef(2, "Rule 2"));
        policy.addRuleSet(multiRule);

        // When
        policy.assignDefaultNamesToAmbiguousRuleSets();

        // Then
        assertThat(catchAll.getName(), is(nullValue()));
        assertThat(category.getName(), is(nullValue()));
        assertThat(tagOnly.getName(), is("Rule Set 1"));
        assertThat(multiRule.getName(), is("Rule Set 2"));
    }

    @Test
    void shouldAssignDefaultNamesToAmbiguousRuleSetsOnLoad(@TempDir Path dir) throws Exception {
        // Given — hand-crafted, as if from an externally authored or older file
        GspmPolicy original = new GspmPolicy("My Policy");
        GspmRuleSet tagOnly = new GspmRuleSet();
        tagOnly.setTags(List.of("FOO"));
        original.addRuleSet(tagOnly);
        original.save(dir);

        // When
        GspmPolicy loaded = GspmPolicy.load(new File(dir.toFile(), "My Policy.policy2"));

        // Then
        assertThat(loaded.getRuleSets(), hasSize(1));
        assertThat(loaded.getRuleSets().get(0).getName(), is("Rule Set 1"));
    }

    @Test
    void shouldReturnEmptyEffectiveThresholdWithNoRuleSets() {
        GspmPolicy policy = new GspmPolicy("P");
        GspmRule rule = testRule("pscan", 10020);
        assertThat(policy.getEffectiveThreshold(rule).isPresent(), is(false));
    }

    @Test
    void shouldResolveCatchAllRuleSetThreshold() {
        GspmPolicy policy = new GspmPolicy("P");
        policy.setDefaultThreshold(AlertThreshold.HIGH);
        GspmRule rule = testRule("pscan", 10020);
        assertThat(policy.getEffectiveThreshold(rule).get(), is(AlertThreshold.HIGH));
    }

    @Test
    void shouldLastMatchWinForOverlappingRuleSets() {
        GspmPolicy policy = new GspmPolicy("P");
        policy.setDefaultThreshold(AlertThreshold.HIGH);
        policy.setRuleThreshold(10020, "rule", AlertThreshold.LOW);
        GspmRule rule = testRule("pscan", 10020);
        assertThat(policy.getEffectiveThreshold(rule).get(), is(AlertThreshold.LOW));
    }

    @Test
    void shouldReturnEmptyEffectiveThresholdRuleSetWithNoRuleSets() {
        GspmPolicy policy = new GspmPolicy("P");
        GspmRule rule = testRule("pscan", 10020);
        assertThat(policy.getEffectiveThresholdRuleSet(rule).isPresent(), is(false));
    }

    @Test
    void shouldReturnTheRuleSetTheEffectiveThresholdCameFrom() {
        GspmPolicy policy = new GspmPolicy("P");
        policy.setDefaultThreshold(AlertThreshold.HIGH);
        GspmRuleSet catchAll = policy.getRuleSets().get(0);
        GspmRule rule = testRule("pscan", 10020);
        assertThat(policy.getEffectiveThresholdRuleSet(rule).get(), sameInstance(catchAll));
    }

    @Test
    void shouldReturnTheLastMatchingRuleSetAsTheEffectiveThresholdRuleSet() {
        GspmPolicy policy = new GspmPolicy("P");
        policy.setDefaultThreshold(AlertThreshold.HIGH);
        policy.setRuleThreshold(10020, "rule", AlertThreshold.LOW);
        GspmRuleSet perRule = policy.getRuleSets().get(policy.getRuleSets().size() - 1);
        GspmRule rule = testRule("pscan", 10020);
        assertThat(policy.getEffectiveThresholdRuleSet(rule).get(), sameInstance(perRule));
    }

    @Test
    void shouldResolvePhaseScopedThresholdForAnyToolInThatPhase() {
        GspmPolicy policy = new GspmPolicy("P");
        policy.findOrCreateCategoryRuleSet(GspmRuleSet.PHASE_PREFIX + "PASSIVE")
                .setThresholdEnum(AlertThreshold.HIGH);
        GspmRule rule = testRule("pscan", 10020);
        assertThat(policy.getEffectiveThreshold(rule).get(), is(AlertThreshold.HIGH));
    }

    @Test
    void shouldLetMoreSpecificCategoryOverridePhaseDefault() {
        GspmPolicy policy = new GspmPolicy("P");
        policy.findOrCreateCategoryRuleSet(GspmRuleSet.PHASE_PREFIX + "PASSIVE")
                .setThresholdEnum(AlertThreshold.HIGH);
        policy.findOrCreateCategoryRuleSet("all.pscan").setThresholdEnum(AlertThreshold.LOW);
        GspmRule pscanRule = testRule("pscan", 10020);
        GspmRule wspscanRule = testRule("wspscan", 110001);
        // The more specific "all.pscan" override wins for pscan rules...
        assertThat(policy.getEffectiveThreshold(pscanRule).get(), is(AlertThreshold.LOW));
        // ...but wspscan rules still fall back to the broader phase-level default.
        assertThat(policy.getEffectiveThreshold(wspscanRule).get(), is(AlertThreshold.HIGH));
    }

    @Test
    void shouldMatchByTag() {
        GspmPolicy policy = new GspmPolicy("P");
        GspmRuleSet rs = new GspmRuleSet();
        rs.setTags(List.of("POLICY_API"));
        rs.setThresholdEnum(AlertThreshold.HIGH);
        policy.getRuleSets().add(rs);
        GspmRule apiRule = testRuleWithTags("pscan", 1, Map.of("POLICY_API", ""));
        GspmRule otherRule = testRule("pscan", 2);
        assertThat(policy.getEffectiveThreshold(apiRule).get(), is(AlertThreshold.HIGH));
        assertThat(policy.getEffectiveThreshold(otherRule).isPresent(), is(false));
    }

    @Test
    void shouldRoundTripThroughYaml(@TempDir Path dir) throws Exception {
        // Given
        GspmPolicy original = new GspmPolicy("My Policy");
        original.setDefaultThreshold(AlertThreshold.HIGH);
        original.setDefaultStrength(AttackStrength.LOW);
        original.findOrCreateCategoryRuleSet("all.ascan").setThresholdEnum(AlertThreshold.MEDIUM);
        original.setRuleThreshold(10020, "Content-Security-Policy", AlertThreshold.LOW);

        // When
        original.save(dir);
        GspmPolicy loaded = GspmPolicy.load(new File(dir.toFile(), "My Policy.policy2"));

        // Then
        assertThat(loaded.getName(), is("My Policy"));
        assertThat(loaded.getFileName(), is("My Policy"));
        assertThat(loaded.getDefaultThreshold().get(), is(AlertThreshold.HIGH));
        assertThat(loaded.getDefaultStrength().get(), is(AttackStrength.LOW));
        GspmRuleSet ascanRuleSet = loaded.findOrCreateCategoryRuleSet("all.ascan");
        assertThat(ascanRuleSet.getThresholdEnum(), is(AlertThreshold.MEDIUM));
        GspmRule rule = testRule("pscan", 10020);
        assertThat(loaded.getEffectiveThreshold(rule).get(), is(AlertThreshold.LOW));
    }

    @Test
    void shouldSaveUsingExplicitFileNameWhenDifferentFromName(@TempDir Path dir) throws Exception {
        // Given
        GspmPolicy policy = new GspmPolicy("Developer CI/CD");
        policy.setFileName("Dev CICD");
        policy.setDefaultThreshold(AlertThreshold.MEDIUM);

        // When
        policy.save(dir);

        // Then
        File saved = new File(dir.toFile(), "Dev CICD.policy2");
        assertThat(saved.exists(), is(true));
        GspmPolicy loaded = GspmPolicy.load(saved);
        assertThat(loaded.getName(), is("Developer CI/CD"));
        assertThat(loaded.getFileName(), is("Dev CICD"));
    }

    @Nested
    class DeleteFile {

        @Test
        void shouldReturnTrueAndDoNothingWhenNeverSavedOrLoaded() {
            // Given
            GspmPolicy policy = new GspmPolicy("P");

            // When / Then
            assertThat(policy.deleteFile(), is(true));
            assertThat(policy.getFile(), is(nullValue()));
        }

        @Test
        void shouldDeleteFileAndClearItOnSuccess(@TempDir Path dir) throws Exception {
            // Given
            GspmPolicy policy = new GspmPolicy("P");
            policy.save(dir);
            File saved = policy.getFile();
            assertThat(saved.exists(), is(true));

            // When
            boolean result = policy.deleteFile();

            // Then
            assertThat(result, is(true));
            assertThat(saved.exists(), is(false));
            assertThat(policy.getFile(), is(nullValue()));
        }

        @Test
        void shouldReturnFalseAndKeepFileWhenDeletionFails() throws Exception {
            // Given
            GspmPolicy policy = new GspmPolicy("P");
            File undeletable = mock(File.class);
            when(undeletable.delete()).thenReturn(false);
            when(undeletable.exists()).thenReturn(true);
            Field fileField = GspmPolicy.class.getDeclaredField("file");
            fileField.setAccessible(true);
            fileField.set(policy, undeletable);

            // When
            boolean result = policy.deleteFile();

            // Then
            assertThat(result, is(false));
            assertThat(policy.getFile(), is(sameInstance(undeletable)));
        }
    }

    @Nested
    class PerRuleOverrides {

        @Test
        void shouldRemoveRuleSetWhenThresholdClearedAndNoStrengthSet() {
            // Given
            GspmPolicy policy = new GspmPolicy("P");
            policy.setRuleThreshold(10020, "rule", AlertThreshold.LOW);

            // When
            policy.setRuleThreshold(10020, "rule", null);

            // Then
            assertThat(policy.getRuleSets(), is(empty()));
        }

        @Test
        void shouldRemoveRuleSetWhenStrengthClearedAndNoThresholdSet() {
            // Given
            GspmPolicy policy = new GspmPolicy("P");
            policy.setRuleStrength(1, "rule", AttackStrength.HIGH);

            // When
            policy.setRuleStrength(1, "rule", null);

            // Then
            assertThat(policy.getRuleSets(), is(empty()));
        }

        @Test
        void shouldKeepRuleSetWhenOnlyThresholdClearedButStrengthRemains() {
            // Given
            GspmPolicy policy = new GspmPolicy("P");
            policy.setRuleThreshold(10020, "rule", AlertThreshold.LOW);
            policy.setRuleStrength(10020, "rule", AttackStrength.HIGH);

            // When
            policy.setRuleThreshold(10020, "rule", null);

            // Then
            assertThat(policy.getRuleSets(), hasSize(1));
            GspmRuleSet rs = policy.getRuleSets().get(0);
            assertThat(rs.getThreshold(), is(nullValue()));
            assertThat(rs.getStrengthEnum(), is(AttackStrength.HIGH));
        }

        @Test
        void clearRuleOverrideShouldRemoveBothThresholdAndStrength() {
            // Given
            GspmPolicy policy = new GspmPolicy("P");
            policy.setRuleThreshold(10020, "rule", AlertThreshold.LOW);
            policy.setRuleStrength(10020, "rule", AttackStrength.HIGH);

            // When
            policy.clearRuleOverride(10020);

            // Then
            assertThat(policy.getRuleSets(), is(empty()));
        }

        @Test
        void clearRuleOverrideShouldNotAffectOtherRules() {
            // Given
            GspmPolicy policy = new GspmPolicy("P");
            policy.setRuleThreshold(10020, "rule", AlertThreshold.LOW);
            policy.setRuleThreshold(10021, "other", AlertThreshold.HIGH);

            // When
            policy.clearRuleOverride(10020);

            // Then
            GspmRule otherRule = testRule("pscan", 10021);
            assertThat(policy.getEffectiveThreshold(otherRule).get(), is(AlertThreshold.HIGH));
            assertThat(policy.getRuleSets(), hasSize(1));
        }

        @Test
        void clearRuleOverrideShouldBeNoOpWhenNoOverrideExists() {
            // Given
            GspmPolicy policy = new GspmPolicy("P");
            policy.setDefaultThreshold(AlertThreshold.HIGH);

            // When
            policy.clearRuleOverride(10020);

            // Then
            assertThat(policy.getRuleSets(), hasSize(1));
            assertThat(policy.getDefaultThreshold().get(), is(AlertThreshold.HIGH));
        }

        @Test
        void clearRuleOverrideShouldNotAffectCategoryOrCatchAllRuleSets() {
            // Given
            GspmPolicy policy = new GspmPolicy("P");
            policy.setDefaultThreshold(AlertThreshold.HIGH);
            policy.findOrCreateCategoryRuleSet("all.ascan").setThresholdEnum(AlertThreshold.MEDIUM);
            policy.setRuleThreshold(10020, "rule", AlertThreshold.LOW);

            // When
            policy.clearRuleOverride(10020);

            // Then
            assertThat(policy.getRuleSets(), hasSize(2));
            GspmRule rule = testRule("ascan", 10020);
            assertThat(policy.getEffectiveThreshold(rule).get(), is(AlertThreshold.MEDIUM));
        }

        @Test
        void clearRuleOverrideShouldRemoveJustThisRuleFromAGroupedLegacyOverride() {
            // Given — mimics GspmLegacyImporter, which groups several rules that share the same
            // threshold/strength into one rule set rather than a dedicated set per rule.
            GspmPolicy policy = new GspmPolicy("P");
            GspmRuleSet grouped = new GspmRuleSet();
            grouped.setThresholdEnum(AlertThreshold.HIGH);
            grouped.addRule(new GspmRuleRef(10020, "Rule A"));
            grouped.addRule(new GspmRuleRef(10021, "Rule B"));
            policy.getRuleSets().add(grouped);

            // When
            policy.clearRuleOverride(10020);

            // Then — only the cleared rule leaves the group; the other rule keeps the override
            GspmRule clearedRule = testRule("ascan", 10020);
            GspmRule otherRule = testRule("ascan", 10021);
            assertThat(policy.getEffectiveThreshold(clearedRule).isPresent(), is(false));
            assertThat(policy.getEffectiveThreshold(otherRule).get(), is(AlertThreshold.HIGH));
            assertThat(policy.getRuleSets(), hasSize(1));
        }

        @Test
        void clearRuleOverrideShouldRemoveGroupedRuleSetOnceItsLastRuleIsCleared() {
            // Given
            GspmPolicy policy = new GspmPolicy("P");
            GspmRuleSet grouped = new GspmRuleSet();
            grouped.setThresholdEnum(AlertThreshold.HIGH);
            grouped.addRule(new GspmRuleRef(10020, "Rule A"));
            grouped.addRule(new GspmRuleRef(10021, "Rule B"));
            policy.getRuleSets().add(grouped);

            // When
            policy.clearRuleOverride(10020);
            policy.clearRuleOverride(10021);

            // Then
            assertThat(policy.getRuleSets(), is(empty()));
        }
    }

    @Nested
    class CategoryRuleSetOrdering {

        @Test
        void shouldInsertCategoryRuleSetsInAscendingKeyLengthOrder() {
            // Given
            GspmPolicy policy = new GspmPolicy("P");
            policy.setDefaultThreshold(AlertThreshold.HIGH);

            // When
            policy.findOrCreateCategoryRuleSet("all.ascan");
            policy.findOrCreateCategoryRuleSet("all.ascan.inject");

            // Then
            List<GspmRuleSet> rs = policy.getRuleSets();
            assertThat(rs.get(0).isCatchAll(), is(true));
            assertThat(rs.get(1).getCategory(), is("all.ascan"));
            assertThat(rs.get(2).getCategory(), is("all.ascan.inject"));
        }

        @Test
        void shouldInsertShorterCategoryBeforeLongerEvenWhenAddedLater() {
            // Given
            GspmPolicy policy = new GspmPolicy("P");
            policy.findOrCreateCategoryRuleSet("all.ascan.inject");

            // When
            policy.findOrCreateCategoryRuleSet("all.ascan");

            // Then
            List<GspmRuleSet> rs = policy.getRuleSets();
            assertThat(rs.get(0).getCategory(), is("all.ascan"));
            assertThat(rs.get(1).getCategory(), is("all.ascan.inject"));
        }

        @Test
        void shouldInsertCategoryRuleSetBeforePerRuleRuleSets() {
            // Given
            GspmPolicy policy = new GspmPolicy("P");
            policy.setRuleThreshold(10020, "test-rule", AlertThreshold.OFF);

            // When
            policy.findOrCreateCategoryRuleSet("all.pscan");

            // Then
            List<GspmRuleSet> rs = policy.getRuleSets();
            assertThat(rs.get(0).getCategory(), is("all.pscan"));
            assertThat(rs.get(rs.size() - 1).isPerRule(10020), is(true));
        }

        @Test
        void shouldReturnExistingCategoryRuleSetWithoutCreatingDuplicate() {
            // Given
            GspmPolicy policy = new GspmPolicy("P");
            GspmRuleSet first = policy.findOrCreateCategoryRuleSet("all.ascan");
            first.setThresholdEnum(AlertThreshold.HIGH);

            // When
            GspmRuleSet second = policy.findOrCreateCategoryRuleSet("all.ascan");

            // Then
            assertThat(second, is(first));
            assertThat(policy.getRuleSets(), hasSize(1));
        }

        @Test
        void hasCategoryRuleSetShouldReflectExistence() {
            // Given
            GspmPolicy policy = new GspmPolicy("P");

            // Then
            assertThat(policy.hasCategoryRuleSet("all.ascan"), is(false));
            assertThat(policy.hasCategoryRuleSet(null), is(false));

            // When
            policy.findOrCreateCategoryRuleSet("all.ascan");
            policy.setDefaultThreshold(AlertThreshold.HIGH);

            // Then
            assertThat(policy.hasCategoryRuleSet("all.ascan"), is(true));
            assertThat(policy.hasCategoryRuleSet(GspmRuleSet.ALL_CATEGORY), is(true));
            assertThat(policy.hasCategoryRuleSet(null), is(true));
            assertThat(policy.hasCategoryRuleSet("all.pscan"), is(false));
        }
    }

    @Nested
    class PerRuleOverrideMerging {

        @Test
        void shouldCreateDedicatedRuleSetForFirstOverride() {
            // Given
            GspmPolicy policy = new GspmPolicy("P");

            // When
            policy.setRuleThreshold(10020, "Rule A", AlertThreshold.OFF);

            // Then
            assertThat(policy.getRuleSets(), hasSize(1));
            GspmRuleSet rs = policy.getRuleSets().get(0);
            assertThat(rs.getRules(), hasSize(1));
            assertThat(rs.getThresholdEnum(), is(AlertThreshold.OFF));
        }

        @Test
        void shouldMergeSecondIdenticalOverrideIntoExistingRuleSet() {
            // Given
            GspmPolicy policy = new GspmPolicy("P");
            policy.setRuleThreshold(10020, "Rule A", AlertThreshold.OFF);

            // When
            policy.setRuleThreshold(10021, "Rule B", AlertThreshold.OFF);

            // Then
            assertThat(policy.getRuleSets(), hasSize(1));
            GspmRuleSet rs = policy.getRuleSets().get(0);
            assertThat(rs.getRules(), hasSize(2));
            assertThat(rs.isPerRule(10020), is(false));
        }

        @Test
        void shouldNotMergeWhenThresholdDiffers() {
            // Given
            GspmPolicy policy = new GspmPolicy("P");
            policy.setRuleThreshold(10020, "Rule A", AlertThreshold.OFF);

            // When
            policy.setRuleThreshold(10021, "Rule B", AlertThreshold.LOW);

            // Then
            assertThat(policy.getRuleSets(), hasSize(2));
        }

        @Test
        void shouldSplitRuleOutOfGroupWhenChangingItsThreshold() {
            // Given
            GspmPolicy policy = new GspmPolicy("P");
            policy.setRuleThreshold(10020, "Rule A", AlertThreshold.OFF);
            policy.setRuleThreshold(10021, "Rule B", AlertThreshold.OFF);

            // When
            policy.setRuleThreshold(10020, "Rule A", AlertThreshold.HIGH);

            // Then
            assertThat(policy.getRuleSets(), hasSize(2));
            GspmRule ruleA = testRule("ascan", 10020);
            GspmRule ruleB = testRule("ascan", 10021);
            assertThat(policy.getEffectiveThreshold(ruleA).get(), is(AlertThreshold.HIGH));
            assertThat(policy.getEffectiveThreshold(ruleB).get(), is(AlertThreshold.OFF));
        }

        @Test
        void shouldSplitAndCarryOverOtherDimensionWhenSharedGroupNeedsDifferentStrength() {
            // Given — A and B share one rule set overriding only threshold
            GspmPolicy policy = new GspmPolicy("P");
            policy.setRuleThreshold(10020, "Rule A", AlertThreshold.OFF);
            policy.setRuleThreshold(10021, "Rule B", AlertThreshold.OFF);

            // When — A alone also needs a strength override
            policy.setRuleStrength(10020, "Rule A", AttackStrength.HIGH);

            // Then — A splits into its own rule set carrying the threshold it had, plus the new
            // strength; B is left in the original group, unaffected
            assertThat(policy.getRuleSets(), hasSize(2));
            GspmRule ruleA = testRule("ascan", 10020);
            GspmRule ruleB = testRule("ascan", 10021);
            assertThat(policy.getEffectiveThreshold(ruleA).get(), is(AlertThreshold.OFF));
            assertThat(policy.getEffectiveStrength(ruleA).get(), is(AttackStrength.HIGH));
            assertThat(policy.getEffectiveThreshold(ruleB).get(), is(AlertThreshold.OFF));
            assertThat(policy.getEffectiveStrength(ruleB).isPresent(), is(false));
        }

        @Test
        void clearingOneRulesOverrideShouldLeaveGroupmateUnaffected() {
            // Given
            GspmPolicy policy = new GspmPolicy("P");
            policy.setRuleThreshold(10020, "Rule A", AlertThreshold.OFF);
            policy.setRuleThreshold(10021, "Rule B", AlertThreshold.OFF);

            // When
            policy.setRuleThreshold(10020, "Rule A", null);

            // Then
            assertThat(policy.getRuleSets(), hasSize(1));
            GspmRule ruleA = testRule("ascan", 10020);
            GspmRule ruleB = testRule("ascan", 10021);
            assertThat(policy.getEffectiveThreshold(ruleA).isPresent(), is(false));
            assertThat(policy.getEffectiveThreshold(ruleB).get(), is(AlertThreshold.OFF));
        }

        @Test
        void soleOwnedRuleSetShouldSupportIndependentThresholdAndStrengthWithoutSplitting() {
            // Given
            GspmPolicy policy = new GspmPolicy("P");
            policy.setRuleThreshold(10020, "Rule A", AlertThreshold.LOW);

            // When
            policy.setRuleStrength(10020, "Rule A", AttackStrength.HIGH);

            // Then — still just the one rule set, now carrying both overrides
            assertThat(policy.getRuleSets(), hasSize(1));
            GspmRuleSet rs = policy.getRuleSets().get(0);
            assertThat(rs.getThresholdEnum(), is(AlertThreshold.LOW));
            assertThat(rs.getStrengthEnum(), is(AttackStrength.HIGH));
        }

        @Test
        void shouldRejoinGroupWhenReSettingSameThreshold() {
            // Given
            GspmPolicy policy = new GspmPolicy("P");
            policy.setRuleThreshold(10020, "Rule A", AlertThreshold.OFF);
            policy.setRuleThreshold(10021, "Rule B", AlertThreshold.OFF);

            // When — redundant re-set of the value the group already has
            policy.setRuleThreshold(10020, "Rule A", AlertThreshold.OFF);

            // Then — no split, still one shared rule set
            assertThat(policy.getRuleSets(), hasSize(1));
            assertThat(policy.getRuleSets().get(0).getRules(), hasSize(2));
        }

        @Test
        void shouldNotMergeIntoTagScopedRuleSetEvenWithMatchingValues() {
            // Given — a tag-scoped rule set that happens to have the same threshold
            GspmPolicy policy = new GspmPolicy("P");
            GspmRuleSet tagScoped = new GspmRuleSet();
            tagScoped.setTags(List.of("POLICY_API"));
            tagScoped.setThresholdEnum(AlertThreshold.OFF);
            policy.getRuleSets().add(tagScoped);

            // When
            policy.setRuleThreshold(10020, "Rule A", AlertThreshold.OFF);

            // Then — a new dedicated rule set is created instead of polluting the tag-scoped one
            assertThat(policy.getRuleSets(), hasSize(2));
            assertThat(tagScoped.getRules(), is(nullValue()));
        }
    }

    @Nested
    class RuleSetListMutation {

        @Test
        void shouldAppendNewRuleSetAtEnd() {
            // Given
            GspmPolicy policy = new GspmPolicy("P");
            policy.setDefaultThreshold(AlertThreshold.HIGH);
            GspmRuleSet added = new GspmRuleSet();
            added.setName("Custom");

            // When
            policy.addRuleSet(added);

            // Then
            List<GspmRuleSet> rs = policy.getRuleSets();
            assertThat(rs, hasSize(2));
            assertThat(rs.get(rs.size() - 1), is(sameInstance(added)));
        }

        @Test
        void shouldRemoveRuleSet() {
            // Given
            GspmPolicy policy = new GspmPolicy("P");
            GspmRuleSet rs = new GspmRuleSet();
            policy.addRuleSet(rs);

            // When
            boolean removed = policy.removeRuleSet(rs);

            // Then
            assertThat(removed, is(true));
            assertThat(policy.getRuleSets(), is(empty()));
        }

        @Test
        void shouldReturnFalseRemovingRuleSetNotInList() {
            // Given
            GspmPolicy policy = new GspmPolicy("P");

            // When / Then
            assertThat(policy.removeRuleSet(new GspmRuleSet()), is(false));
        }

        @Test
        void shouldMoveRuleSetUpAndDown() {
            // Given
            GspmPolicy policy = new GspmPolicy("P");
            GspmRuleSet a = new GspmRuleSet();
            GspmRuleSet b = new GspmRuleSet();
            GspmRuleSet c = new GspmRuleSet();
            policy.addRuleSet(a);
            policy.addRuleSet(b);
            policy.addRuleSet(c);

            // When
            policy.moveRuleSet(c, -1);

            // Then
            assertThat(policy.getRuleSets(), is(List.of(a, c, b)));

            // When
            policy.moveRuleSet(a, 1);

            // Then
            assertThat(policy.getRuleSets(), is(List.of(c, a, b)));
        }

        @Test
        void shouldNoOpMovingPastListBoundaries() {
            // Given
            GspmPolicy policy = new GspmPolicy("P");
            GspmRuleSet a = new GspmRuleSet();
            GspmRuleSet b = new GspmRuleSet();
            policy.addRuleSet(a);
            policy.addRuleSet(b);

            // When
            policy.moveRuleSet(a, -1);
            policy.moveRuleSet(b, 1);

            // Then
            assertThat(policy.getRuleSets(), is(List.of(a, b)));
        }

        @Test
        void shouldNoOpMovingRuleSetNotInList() {
            // Given
            GspmPolicy policy = new GspmPolicy("P");
            policy.addRuleSet(new GspmRuleSet());

            // When / Then — no exception
            policy.moveRuleSet(new GspmRuleSet(), -1);
        }
    }

    private static GspmRule testRule(String tool, int id) {
        return testRuleWithTags(tool, id, Collections.emptyMap());
    }

    private static GspmRule testRuleWithTags(String tool, int id, Map<String, String> tags) {
        return new GspmRule() {
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
                return tags;
            }

            @Override
            public boolean isEnabled() {
                return true;
            }

            @Override
            public void setEnabled(boolean enabled) {}

            @Override
            public AlertThreshold getAlertThreshold() {
                return AlertThreshold.MEDIUM;
            }

            @Override
            public void setAlertThreshold(AlertThreshold threshold) {}

            @Override
            public AttackStrength getAttackStrength() {
                return null;
            }

            @Override
            public void setAttackStrength(AttackStrength strength) {}
        };
    }
}
