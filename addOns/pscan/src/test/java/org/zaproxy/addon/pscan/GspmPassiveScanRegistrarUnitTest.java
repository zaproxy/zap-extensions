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
package org.zaproxy.addon.pscan;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.commonlib.gspm.GspmRegistry;
import org.zaproxy.addon.commonlib.gspm.GspmRule;
import org.zaproxy.addon.commonlib.gspm.GspmScanRuleRegistrar;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;
import org.zaproxy.zap.testutils.TestUtils;

/**
 * Unit test for {@link GspmPassiveScanRegistrar}, focused on how it maps passive scanners to {@link
 * GspmRule}s. Add-on attribution is resolved via {@code ExtensionFactory.getAddOnLoader()}, which
 * isn't set up in this unit test context, so it isn't exercised here (mirroring {@code
 * GspmActiveScanRegistrarUnitTest}); every rule here is registered without an owning add-on.
 */
class GspmPassiveScanRegistrarUnitTest extends TestUtils {

    private GspmPassiveScanRegistrar registrar;
    private GspmScanRuleRegistrar scanRuleRegistrar;
    private GspmRegistry registry;
    private List<PluginPassiveScanner> scanRules;

    @BeforeEach
    void setUp() throws Exception {
        mockMessages(new ExtensionPassiveScan2());

        registrar = new GspmPassiveScanRegistrar();
        registry = new GspmRegistry();
        scanRules = new ArrayList<>();

        PassiveScannersManager scannersManager = mock(PassiveScannersManager.class);
        lenient()
                .when(scannersManager.getScanRules())
                .thenAnswer(inv -> new ArrayList<>(scanRules));

        setField(registrar, "scannersManager", scannersManager);
        scanRuleRegistrar = (GspmScanRuleRegistrar) getField(registrar, "scanRuleRegistrar");
        // Registers the tool and sets scanRuleRegistrar's registry; scanRules is empty at this
        // point, so this registers zero rules.
        scanRuleRegistrar.registerRulesWithGspm(registry);
    }

    @AfterAll
    static void cleanUp() {
        Constant.messages = null;
    }

    @Test
    void shouldRegisterAllScannersOnInitialRegistration() {
        // Given
        scanRules.add(new TestScanner(200, "Rule A"));
        scanRules.add(new TestScanner(201, "Rule B"));

        // When
        scanRuleRegistrar.registerRulesWithGspm(registry);

        // Then
        List<GspmRule> rules = registry.getRulesByTool(GspmPassiveScanRegistrar.TOOL);
        assertThat(rules, hasSize(2));
        assertThat(rules.stream().map(GspmRule::getId).toList(), containsInAnyOrder(200, 201));
    }

    @Test
    void shouldSkipScannerWithNoPluginIdOnInitialRegistration() {
        // Given
        scanRules.add(new TestScanner(-1, "No id"));

        // When
        scanRuleRegistrar.registerRulesWithGspm(registry);

        // Then
        assertThat(registry.getAllRules(), is(empty()));
    }

    @Test
    void shouldRegisterRuleAddedDirectly() {
        // Given — e.g. a script-backed rule, added at runtime via
        // ExtensionPassiveScan2.PassiveScannersManagerImpl.add().
        // When
        registrar.ruleAdded(new TestScanner(101, "Extra Rule"));

        // Then
        assertThat(registry.isRegistered(101), is(true));
        List<GspmRule> rules = registry.getRulesByTool(GspmPassiveScanRegistrar.TOOL);
        assertThat(rules, hasSize(1));
        assertThat(rules.get(0).getId(), is(101));
    }

    @Test
    void shouldSkipRuleAddedDirectlyWithNoPluginId() {
        // When
        registrar.ruleAdded(new TestScanner(-1, "No id"));

        // Then
        assertThat(registry.getAllRules(), is(empty()));
    }

    @Test
    void shouldDoNothingWhenRuleAddedDirectlyBeforeInitialRegistration() {
        // Given — registerRulesWithGspm was never called on this registrar/registry pairing.
        GspmPassiveScanRegistrar freshRegistrar = new GspmPassiveScanRegistrar();

        // When / Then
        assertDoesNotThrow(() -> freshRegistrar.ruleAdded(new TestScanner(103, "Rule")));
    }

    @Test
    void shouldUnregisterRuleRemovedDirectly() {
        // Given
        registrar.ruleAdded(new TestScanner(106, "Rule"));
        assertThat(registry.isRegistered(106), is(true));

        // When
        registrar.ruleRemoved(106);

        // Then
        assertThat(registry.isRegistered(106), is(false));
    }

    @Test
    void shouldDoNothingWhenRemovingRuleNotRegisteredDirectly() {
        // When / Then
        assertDoesNotThrow(() -> registrar.ruleRemoved(999));
    }

    private static void setField(GspmPassiveScanRegistrar target, String name, Object value)
            throws Exception {
        Field field = GspmPassiveScanRegistrar.class.getDeclaredField(name);
        field.setAccessible(true);
        field.set(target, value);
    }

    private static Object getField(GspmPassiveScanRegistrar target, String name) throws Exception {
        Field field = GspmPassiveScanRegistrar.class.getDeclaredField(name);
        field.setAccessible(true);
        return field.get(target);
    }

    private static class TestScanner extends PluginPassiveScanner {

        private final int id;
        private final String name;

        TestScanner(int id, String name) {
            this.id = id;
            this.name = name;
        }

        @Override
        public int getPluginId() {
            return id;
        }

        @Override
        public String getName() {
            return name;
        }
    }
}
