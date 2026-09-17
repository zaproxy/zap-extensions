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
import static org.hamcrest.Matchers.is;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.zaproxy.zap.control.AddOn;

class GspmRuleSetUnitTest {

    @Nested
    class Matches {

        @Test
        void catchAllMatchesEveryRule() {
            // Given
            GspmRuleSet rs = new GspmRuleSet();

            // When / Then
            assertThat(rs.matches(rule("pscan", 1)), is(true));
            assertThat(rs.matches(rule("ascan", 999)), is(true));
        }

        @Test
        void matchesByExplicitRuleId() {
            // Given
            GspmRuleSet rs = new GspmRuleSet();
            rs.addRule(new GspmRuleRef(42, "Test Rule"));

            // When / Then
            assertThat(rs.matches(rule("pscan", 42)), is(true));
            assertThat(rs.matches(rule("pscan", 99)), is(false));
        }

        @Test
        void matchesByTag() {
            // Given
            GspmRuleSet rs = new GspmRuleSet();
            rs.setTags(List.of("POLICY_API"));

            // When / Then
            assertThat(rs.matches(ruleWithTags("pscan", 1, Map.of("POLICY_API", ""))), is(true));
            assertThat(rs.matches(ruleWithTags("pscan", 2, Map.of("OTHER_TAG", ""))), is(false));
        }

        @Test
        void categoryMatchesExactKey() {
            // Given
            GspmRuleSet rs = new GspmRuleSet();
            rs.setCategory("all.ascan");

            // When / Then — tool=ascan, no hierarchy → key = "all.ascan"
            assertThat(rs.matches(rule("ascan", 1)), is(true));
        }

        @Test
        void categoryDoesNotMatchDifferentTool() {
            // Given
            GspmRuleSet rs = new GspmRuleSet();
            rs.setCategory("all.ascan");

            // When / Then
            assertThat(rs.matches(rule("pscan", 1)), is(false));
        }

        @Test
        void categoryMatchesChildKey() {
            // Given
            GspmRuleSet rs = new GspmRuleSet();
            rs.setCategory("all.ascan");
            // categories=[GspmCategory("inject",...)] → category key = "all.ascan.inject"
            GspmRule child =
                    ruleWithCategories(
                            "ascan", 1, List.of(new GspmCategory("inject", "Injection")));

            // When / Then
            assertThat(rs.matches(child), is(true));
        }

        @Test
        void categoryMatchesDeepChildKey() {
            // Given
            GspmRuleSet rs = new GspmRuleSet();
            rs.setCategory("all.ascan");
            // categories=[GspmCategory("inject"),GspmCategory("sqli")] → key =
            // "all.ascan.inject.sqli"
            GspmRule deepChild =
                    ruleWithCategories(
                            "ascan",
                            1,
                            List.of(
                                    new GspmCategory("inject", "Injection"),
                                    new GspmCategory("sqli", "SQLi")));

            // When / Then
            assertThat(rs.matches(deepChild), is(true));
        }

        @Test
        void categoryDoesNotMatchParentKey() {
            // Given — more-specific category should NOT match a rule whose key is the parent
            GspmRuleSet rs = new GspmRuleSet();
            rs.setCategory("all.ascan.inject");

            // When / Then — tool=ascan, no hierarchy → key = "all.ascan"
            assertThat(rs.matches(rule("ascan", 1)), is(false));
        }

        @Test
        void categoryDoesNotMatchSiblingWithSharedPrefixButNoDotSeparator() {
            // Given — verifies the dot is appended before startsWith check
            GspmRuleSet rs = new GspmRuleSet();
            rs.setCategory("all.ascan");
            // tool "ascanext" → key = "all.ascanext" (shares "all.ascan" prefix but no dot after)
            GspmRule sibling = rule("ascanext", 1);

            // When / Then
            assertThat(rs.matches(sibling), is(false));
        }

        @Test
        void statusMatchesSameStatus() {
            // Given
            GspmRuleSet rs = new GspmRuleSet();
            rs.setStatus("alpha");

            // When / Then
            assertThat(rs.matches(ruleWithStatus("ascan", 1, AddOn.Status.alpha)), is(true));
        }

        @Test
        void statusIsCaseInsensitive() {
            // Given
            GspmRuleSet rs = new GspmRuleSet();
            rs.setStatus("ALPHA");

            // When / Then
            assertThat(rs.matches(ruleWithStatus("ascan", 1, AddOn.Status.alpha)), is(true));
        }

        @Test
        void statusDoesNotMatchDifferentStatus() {
            // Given
            GspmRuleSet rs = new GspmRuleSet();
            rs.setStatus("alpha");

            // When / Then
            assertThat(rs.matches(ruleWithStatus("ascan", 1, AddOn.Status.release)), is(false));
        }

        @Test
        void statusAndCategoryBothMustMatch() {
            // Given
            GspmRuleSet rs = new GspmRuleSet();
            rs.setCategory("all.ascan");
            rs.setStatus("alpha");
            GspmRule matching = ruleWithStatus("ascan", 1, AddOn.Status.alpha);
            GspmRule wrongStatus = ruleWithStatus("ascan", 2, AddOn.Status.release);
            GspmRule wrongCategory = ruleWithStatus("pscan", 3, AddOn.Status.alpha);

            // When / Then
            assertThat(rs.matches(matching), is(true));
            assertThat(rs.matches(wrongStatus), is(false));
            assertThat(rs.matches(wrongCategory), is(false));
        }
    }

    @Nested
    class RuleCategoryKey {

        @Test
        void noCategoriesProducesToolOnlyKey() {
            // Given
            GspmRule r = rule("pscan", 1);

            // When / Then
            assertThat(GspmRuleSet.ruleCategoryKey(r), is("all.pscan"));
        }

        @Test
        void singleCategoryProducesSingleSegmentKey() {
            // Given
            GspmRule r =
                    ruleWithCategories(
                            "ascan", 1, List.of(new GspmCategory("inject", "Injection")));

            // When / Then
            assertThat(GspmRuleSet.ruleCategoryKey(r), is("all.ascan.inject"));
        }

        @Test
        void multiLevelCategoriesBuildNestedKey() {
            // Given
            GspmRule r =
                    ruleWithCategories(
                            "ascan",
                            1,
                            List.of(
                                    new GspmCategory("inject", "Injection"),
                                    new GspmCategory("sqli", "SQLi")));

            // When / Then
            assertThat(GspmRuleSet.ruleCategoryKey(r), is("all.ascan.inject.sqli"));
        }
    }

    // -- helpers --

    private static GspmRule rule(String tool, int id) {
        return ruleWithCategories(tool, id, Collections.emptyList());
    }

    private static GspmRule ruleWithTags(String tool, int id, Map<String, String> tags) {
        return new StubRule(tool, id, Collections.emptyList(), tags, AddOn.Status.unknown);
    }

    private static GspmRule ruleWithCategories(String tool, int id, List<GspmCategory> categories) {
        return new StubRule(tool, id, categories, Collections.emptyMap(), AddOn.Status.unknown);
    }

    private static GspmRule ruleWithStatus(String tool, int id, AddOn.Status status) {
        return new StubRule(tool, id, Collections.emptyList(), Collections.emptyMap(), status);
    }

    private static class StubRule implements GspmRule {
        private final String tool;
        private final int id;
        private final List<GspmCategory> categories;
        private final Map<String, String> alertTags;
        private final AddOn.Status status;

        StubRule(
                String tool,
                int id,
                List<GspmCategory> categories,
                Map<String, String> alertTags,
                AddOn.Status status) {
            this.tool = tool;
            this.id = id;
            this.categories = categories;
            this.alertTags = alertTags;
            this.status = status;
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
        public List<GspmCategory> getCategories() {
            return categories;
        }

        @Override
        public Map<String, String> getAlertTags() {
            return alertTags;
        }

        @Override
        public AddOn.Status getStatus() {
            return status;
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
    }
}
