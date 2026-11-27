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

import java.nio.file.Files;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.parosproxy.paros.core.scanner.ScannerParam;
import org.zaproxy.addon.commonlib.ExtensionCommonlib;
import org.zaproxy.addon.commonlib.gspm.GspmCategory;
import org.zaproxy.addon.commonlib.gspm.GspmPhase;
import org.zaproxy.addon.commonlib.gspm.GspmPolicy;
import org.zaproxy.addon.commonlib.gspm.GspmRegistry;
import org.zaproxy.addon.commonlib.gspm.GspmRule;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/** Unit test for {@link GspmDefaultPolicy}. */
class GspmDefaultPolicyUnitTest extends TestUtils {

    private GspmRegistry registry;
    private GspmParam param;
    private ScannerParam scannerParam;
    private GspmPolicy defaultPolicy;
    private GspmDefaultPolicy gspmDefaultPolicy;

    @BeforeEach
    void setUp() throws Exception {
        mockMessages(new ExtensionCommonlib());
        setUpZap();
        Files.createDirectories(Constant.getPoliciesDir().toPath());

        registry = new GspmRegistry();
        defaultPolicy = new GspmPolicy(GspmRegistry.getDefaultPolicyName());
        defaultPolicy.setDefaultThreshold(AlertThreshold.MEDIUM);
        registry.addPolicy(defaultPolicy);
        ZapXmlConfiguration config = new ZapXmlConfiguration();
        param = new GspmParam();
        param.load(config);
        scannerParam = new ScannerParam();
        scannerParam.load(config);
        gspmDefaultPolicy = new GspmDefaultPolicy(registry, param, () -> scannerParam);
    }

    @AfterEach
    void cleanUp() {
        gspmDefaultPolicy.stop();
        Constant.messages = null;
    }

    @Test
    void shouldUseDefaultPolicyOfOptions() {
        // Given
        registry.addPolicy(new GspmPolicy("Other"));
        scannerParam.setDefaultPolicy("Other");
        // When
        gspmDefaultPolicy.start();
        // Then
        assertThat(gspmDefaultPolicy.getName(), is(equalTo("Other")));
        assertThat(registry.getCurrentPolicy(), is(equalTo("Other")));
    }

    @Test
    void shouldUseBuiltInDefaultPolicyIfOptionsPolicyMissing() {
        // Given
        scannerParam.setDefaultPolicy("Missing");
        // When
        gspmDefaultPolicy.start();
        // Then
        assertThat(gspmDefaultPolicy.getName(), is(equalTo(GspmRegistry.getDefaultPolicyName())));
        assertThat(
                scannerParam.getDefaultPolicy(), is(equalTo(GspmRegistry.getDefaultPolicyName())));
    }

    @Test
    void shouldPersistDefaultPolicyChosen() {
        // Given
        registry.addPolicy(new GspmPolicy("Other"));
        gspmDefaultPolicy.start();
        // When
        gspmDefaultPolicy.setName("Other");
        // Then
        assertThat(scannerParam.getDefaultPolicy(), is(equalTo("Other")));
    }

    @Test
    void shouldFollowDefaultPolicyChangedInOptions() {
        // Given
        registry.addPolicy(new GspmPolicy("Other"));
        gspmDefaultPolicy.start();
        scannerParam.setDefaultPolicy("Other");
        // When
        gspmDefaultPolicy.optionsChanged();
        // Then
        assertThat(gspmDefaultPolicy.getName(), is(equalTo("Other")));
    }

    @Test
    void shouldApplyDefaultPolicyToPassiveRules() {
        // Given
        param.setPassiveImported();
        TestRule passive = new TestRule(1, GspmPhase.PASSIVE);
        TestRule active = new TestRule(2, GspmPhase.ACTIVE);
        registry.registerRule(passive);
        registry.registerRule(active);
        GspmPolicy other = new GspmPolicy("Other");
        other.setDefaultThreshold(AlertThreshold.OFF);
        registry.addPolicy(other);
        gspmDefaultPolicy.start();
        // When
        gspmDefaultPolicy.setName("Other");
        // Then
        assertThat(passive.isEnabled(), is(false));
        assertThat(active.isEnabled(), is(true));
    }

    @Test
    void shouldApplyDefaultPolicyToPassiveRulesRegisteredLater() {
        // Given
        param.setPassiveImported();
        defaultPolicy.setDefaultThreshold(AlertThreshold.HIGH);
        gspmDefaultPolicy.start();
        TestRule passive = new TestRule(1, GspmPhase.PASSIVE);
        // When
        registry.registerRule(passive);
        // Then
        assertThat(passive.getAlertThreshold(), is(equalTo(AlertThreshold.HIGH)));
    }

    @Test
    void shouldApplyDefaultPolicyWhenSaved() throws Exception {
        // Given
        param.setPassiveImported();
        TestRule passive = new TestRule(1, GspmPhase.PASSIVE);
        registry.registerRule(passive);
        gspmDefaultPolicy.start();
        defaultPolicy.setRuleThreshold(1, "Rule 1", AlertThreshold.LOW);
        // When
        defaultPolicy.save();
        // Then
        assertThat(passive.getAlertThreshold(), is(equalTo(AlertThreshold.LOW)));
    }

    @Test
    void shouldFallBackToBuiltInDefaultPolicyIfRemoved() {
        // Given
        registry.addPolicy(new GspmPolicy("Other"));
        gspmDefaultPolicy.start();
        gspmDefaultPolicy.setName("Other");
        // When
        registry.removePolicy("Other");
        // Then
        assertThat(gspmDefaultPolicy.getName(), is(equalTo(GspmRegistry.getDefaultPolicyName())));
    }

    @Test
    void shouldPersistRenamedDefaultPolicy() {
        // Given
        GspmPolicy other = new GspmPolicy("Other");
        registry.addPolicy(other);
        gspmDefaultPolicy.start();
        gspmDefaultPolicy.setName("Other");
        // When
        registry.renamePolicy(other, "Renamed");
        // Then
        assertThat(scannerParam.getDefaultPolicy(), is(equalTo("Renamed")));
    }

    @Test
    void shouldImportPassiveRulesSettingsOnce() {
        // Given
        TestRule disabled = new TestRule(1, GspmPhase.PASSIVE);
        disabled.setEnabled(false);
        TestRule high = new TestRule(2, GspmPhase.PASSIVE);
        high.setAlertThreshold(AlertThreshold.HIGH);
        TestRule unchanged = new TestRule(3, GspmPhase.PASSIVE);
        registry.registerRule(disabled);
        // When
        gspmDefaultPolicy.start();
        registry.registerRule(high);
        registry.registerRule(unchanged);
        // Then
        assertThat(param.isPassiveImported(), is(true));
        assertThat(disabled.isEnabled(), is(false));
        assertThat(high.isEnabled(), is(true));
        assertThat(high.getAlertThreshold(), is(equalTo(AlertThreshold.HIGH)));
        assertThat(unchanged.getAlertThreshold(), is(equalTo(AlertThreshold.MEDIUM)));
        assertThat(
                defaultPolicy.getEffectiveThreshold(disabled).get(),
                is(equalTo(AlertThreshold.OFF)));
        assertThat(
                defaultPolicy.getEffectiveThreshold(high).get(), is(equalTo(AlertThreshold.HIGH)));
        assertThat(
                defaultPolicy.getEffectiveThreshold(unchanged).get(),
                is(equalTo(AlertThreshold.MEDIUM)));
    }

    @Test
    void shouldNotImportPassiveRulesSettingsIfAlreadyImported() {
        // Given
        param.setPassiveImported();
        TestRule disabled = new TestRule(1, GspmPhase.PASSIVE);
        disabled.setEnabled(false);
        registry.registerRule(disabled);
        // When
        gspmDefaultPolicy.start();
        // Then
        assertThat(disabled.isEnabled(), is(true));
        assertThat(
                defaultPolicy.getEffectiveThreshold(disabled).get(),
                is(equalTo(AlertThreshold.MEDIUM)));
    }

    @Test
    void shouldNotConfigureRulesOnceStopped() {
        // Given
        param.setPassiveImported();
        defaultPolicy.setDefaultThreshold(AlertThreshold.HIGH);
        gspmDefaultPolicy.start();
        gspmDefaultPolicy.stop();
        TestRule passive = new TestRule(1, GspmPhase.PASSIVE);
        // When
        registry.registerRule(passive);
        // Then
        assertThat(passive.getAlertThreshold(), is(equalTo(AlertThreshold.MEDIUM)));
        assertThat(gspmDefaultPolicy.isStarted(), is(false));
    }

    @Test
    void shouldUseOriginalSettingsOfRulesNotConfiguredByPolicy() {
        // Given
        param.setPassiveImported();
        TestRule rule = new TestRule(1, GspmPhase.PASSIVE);
        rule.setAlertThreshold(AlertThreshold.LOW);
        registry.registerRule(rule);
        defaultPolicy.setRuleThreshold(1, "Rule 1", AlertThreshold.OFF);
        GspmPolicy unconfigured = new GspmPolicy("Unconfigured");
        registry.addPolicy(unconfigured);
        gspmDefaultPolicy.start();
        // When
        gspmDefaultPolicy.setName("Unconfigured");
        // Then
        assertThat(rule.isEnabled(), is(true));
        assertThat(rule.getAlertThreshold(), is(equalTo(AlertThreshold.LOW)));
    }

    @Test
    void shouldNotKeepThresholdOfPreviousPolicy() {
        // Given
        param.setPassiveImported();
        TestRule rule = new TestRule(1, GspmPhase.PASSIVE);
        registry.registerRule(rule);
        defaultPolicy.setDefaultThreshold(AlertThreshold.HIGH);
        registry.addPolicy(new GspmPolicy("Unconfigured"));
        gspmDefaultPolicy.start();
        // When
        gspmDefaultPolicy.setName("Unconfigured");
        // Then
        assertThat(rule.getAlertThreshold(), is(equalTo(AlertThreshold.MEDIUM)));
    }

    @Test
    void shouldImportIntoPersistedDefaultPolicy() {
        // Given
        GspmPolicy other = new GspmPolicy("Other");
        other.setDefaultThreshold(AlertThreshold.MEDIUM);
        registry.addPolicy(other);
        scannerParam.setDefaultPolicy("Other");
        TestRule disabled = new TestRule(1, GspmPhase.PASSIVE);
        disabled.setEnabled(false);
        registry.registerRule(disabled);
        // When
        gspmDefaultPolicy.start();
        // Then
        assertThat(disabled.isEnabled(), is(false));
        assertThat(other.getEffectiveThreshold(disabled).get(), is(equalTo(AlertThreshold.OFF)));
    }

    @Test
    void shouldNotStartWithoutPolicies() {
        // Given
        registry.removePolicy(GspmRegistry.getDefaultPolicyName());
        // When
        gspmDefaultPolicy.start();
        // Then
        assertThat(gspmDefaultPolicy.isStarted(), is(false));
        assertThat(param.isPassiveImported(), is(false));
    }

    @Test
    void shouldRestoreOriginalSettingsWhenStopped() {
        // Given
        param.setPassiveImported();
        TestRule rule = new TestRule(1, GspmPhase.PASSIVE);
        registry.registerRule(rule);
        defaultPolicy.setDefaultThreshold(AlertThreshold.OFF);
        gspmDefaultPolicy.start();
        // When
        gspmDefaultPolicy.stop();
        // Then
        assertThat(rule.isEnabled(), is(true));
    }

    private static class TestRule implements GspmRule {

        private final int id;
        private final GspmPhase phase;
        private boolean enabled = true;
        private AlertThreshold threshold = AlertThreshold.MEDIUM;

        TestRule(int id, GspmPhase phase) {
            this.id = id;
            this.phase = phase;
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
            return phase == GspmPhase.ACTIVE ? "ascan" : "pscan";
        }

        @Override
        public GspmPhase getPhase() {
            return phase;
        }

        @Override
        public List<GspmCategory> getCategories() {
            return List.of(new GspmCategory("cat", "Cat"));
        }

        @Override
        public Map<String, String> getAlertTags() {
            return Map.of();
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
            return phase == GspmPhase.ACTIVE ? AttackStrength.MEDIUM : null;
        }

        @Override
        public void setAttackStrength(AttackStrength strength) {
            // Not needed.
        }
    }
}
