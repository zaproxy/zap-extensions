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
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.File;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;

@SuppressWarnings("OptionalGetWithoutIsPresent")
class GspmPolicyUnitTest {

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
        original.save(dir.toFile());
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
        policy.save(dir.toFile());

        // Then
        File saved = new File(dir.toFile(), "Dev CICD.policy2");
        assertThat(saved.exists(), is(true));
        GspmPolicy loaded = GspmPolicy.load(saved);
        assertThat(loaded.getName(), is("Developer CI/CD"));
        assertThat(loaded.getFileName(), is("Dev CICD"));
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
    }

    // -- helpers --

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
