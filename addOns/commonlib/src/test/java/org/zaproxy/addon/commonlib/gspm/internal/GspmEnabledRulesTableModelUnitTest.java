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

import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.zaproxy.addon.commonlib.ExtensionCommonlib;
import org.zaproxy.addon.commonlib.gspm.GspmCategory;
import org.zaproxy.addon.commonlib.gspm.GspmPhase;
import org.zaproxy.addon.commonlib.gspm.GspmPolicy;
import org.zaproxy.addon.commonlib.gspm.GspmRule;
import org.zaproxy.addon.commonlib.gspm.GspmRuleRef;
import org.zaproxy.addon.commonlib.gspm.GspmRuleSet;
import org.zaproxy.zap.control.AddOn;
import org.zaproxy.zap.testutils.TestUtils;

class GspmEnabledRulesTableModelUnitTest extends TestUtils {

    @BeforeAll
    static void setupMessages() {
        mockMessages(new ExtensionCommonlib());
    }

    @AfterAll
    static void cleanUpMessages() {
        Constant.messages = null;
    }

    @Test
    void shouldShowPolicyDefaultWhenNothingInThePolicyOverridesTheRule() {
        // Given — mirrors a policy that disables everything via a category-scoped OFF and
        // re-enables specific rules by id, leaving other tools (e.g. pscan) untouched by anything
        // in the policy at all.
        GspmPolicy policy = new GspmPolicy("API");
        GspmRuleSet ascanOff = new GspmRuleSet();
        ascanOff.setCategory("all.ascan");
        ascanOff.setThresholdEnum(AlertThreshold.OFF);
        policy.addRuleSet(ascanOff);
        GspmRuleSet reEnabled = new GspmRuleSet();
        reEnabled.setName("Rule Set 1");
        reEnabled.addRule(new GspmRuleRef(40018, "SQL Injection"));
        reEnabled.setThresholdEnum(AlertThreshold.MEDIUM);
        policy.addRuleSet(reEnabled);
        GspmRule pscanRule = stubRule("pscan", 2, AlertThreshold.MEDIUM);

        GspmEnabledRulesTableModel model = new GspmEnabledRulesTableModel(policy);
        model.setRules(List.of(pscanRule));

        // Then
        assertThat(
                model.getValueAt(0, GspmEnabledRulesTableModel.COL_RULESET), is("Policy Default"));
    }

    @Test
    void shouldShowRuleSetNameWhenAnExplicitRuleOverrideEnablesIt() {
        // Given
        GspmPolicy policy = new GspmPolicy("API");
        GspmRuleSet ascanOff = new GspmRuleSet();
        ascanOff.setCategory("all.ascan");
        ascanOff.setThresholdEnum(AlertThreshold.OFF);
        policy.addRuleSet(ascanOff);
        GspmRuleSet reEnabled = new GspmRuleSet();
        reEnabled.setName("Rule Set 1");
        reEnabled.addRule(new GspmRuleRef(40018, "SQL Injection"));
        reEnabled.setThresholdEnum(AlertThreshold.MEDIUM);
        policy.addRuleSet(reEnabled);
        GspmRule sqlInjection = stubRule("ascan", 40018, AlertThreshold.MEDIUM);

        GspmEnabledRulesTableModel model = new GspmEnabledRulesTableModel(policy);
        model.setRules(List.of(sqlInjection));

        // Then
        assertThat(model.getValueAt(0, GspmEnabledRulesTableModel.COL_RULESET), is("Rule Set 1"));
    }

    @Test
    void shouldShowCatchAllWhenOnlyTheCatchAllEnablesIt() {
        // Given
        GspmPolicy policy = new GspmPolicy("P");
        policy.setDefaultThreshold(AlertThreshold.MEDIUM);
        GspmRule rule = stubRule("pscan", 1, AlertThreshold.MEDIUM);

        GspmEnabledRulesTableModel model = new GspmEnabledRulesTableModel(policy);
        model.setRules(List.of(rule));

        // Then
        assertThat(model.getValueAt(0, GspmEnabledRulesTableModel.COL_RULESET), is("Catch-all"));
    }

    private static GspmRule stubRule(String tool, int id, AlertThreshold threshold) {
        return new StubRule(tool, id, threshold);
    }

    private static class StubRule implements GspmRule {
        private final String tool;
        private final int id;
        private final AlertThreshold threshold;

        StubRule(String tool, int id, AlertThreshold threshold) {
            this.tool = tool;
            this.id = id;
            this.threshold = threshold;
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
            return GspmPhase.ACTIVE;
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
            return null;
        }

        @Override
        public void setAttackStrength(AttackStrength strength) {}

        @Override
        public AddOn.Status getStatus() {
            return AddOn.Status.unknown;
        }
    }
}
