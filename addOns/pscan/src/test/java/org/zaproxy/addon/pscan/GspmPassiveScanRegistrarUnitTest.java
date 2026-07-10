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
import org.zaproxy.zap.control.AddOn;
import org.zaproxy.zap.extension.AddOnInstallationStatusListener.StatusUpdate;
import org.zaproxy.zap.extension.AddOnInstallationStatusListener.StatusUpdate.Status;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;
import org.zaproxy.zap.testutils.TestUtils;

/**
 * Unit test for {@link GspmPassiveScanRegistrar}, focused on how it maps passive scanners to {@link
 * GspmRule}s and matches them to add-ons. The generic add-on install/uninstall bookkeeping it
 * delegates to is covered by {@code GspmScanRuleRegistrarUnitTest} in commonlib.
 */
class GspmPassiveScanRegistrarUnitTest extends TestUtils {

    private GspmScanRuleRegistrar scanRuleRegistrar;
    private GspmRegistry registry;
    private List<PluginPassiveScanner> scanRules;

    @BeforeEach
    void setUp() throws Exception {
        mockMessages(new ExtensionPassiveScan2());

        GspmPassiveScanRegistrar registrar = new GspmPassiveScanRegistrar();
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
    void shouldRegisterScannerAddedForInstalledAddOn() {
        // Given
        AddOn addOn = addOnWithRule("Extra Add-on", TestScanner.class);
        scanRules.add(new TestScanner(101, "Extra Rule"));

        // When
        scanRuleRegistrar.update(statusUpdate(Status.INSTALLED, addOn));

        // Then
        assertThat(registry.isRegistered(101), is(true));
        List<GspmRule> rules = registry.getRulesByTool(GspmPassiveScanRegistrar.TOOL);
        assertThat(rules, hasSize(1));
        assertThat(rules.get(0).getId(), is(101));
        assertThat(rules.get(0).getAddOnName(), is("Extra Add-on"));
    }

    @Test
    void shouldIgnoreScannersNotBelongingToInstalledAddOn() {
        // Given
        AddOn addOn = addOnWithRule("Extra Add-on", TestScanner.class);
        scanRules.add(new OtherScanner(102));

        // When
        scanRuleRegistrar.update(statusUpdate(Status.INSTALLED, addOn));

        // Then
        assertThat(registry.getAllRules(), is(empty()));
    }

    @Test
    void shouldSkipScannerWithNoPluginIdOnInstall() {
        // Given
        AddOn addOn = addOnWithRule("Extra Add-on", TestScanner.class);
        scanRules.add(new TestScanner(-1, "No id"));

        // When
        scanRuleRegistrar.update(statusUpdate(Status.INSTALLED, addOn));

        // Then
        assertThat(registry.getAllRules(), is(empty()));
    }

    @Test
    void shouldDoNothingWhenInstalledAddOnHasNoPscanRules() {
        // Given
        AddOn addOn = addOnWithNoRules("Add-on");
        scanRules.add(new TestScanner(104, "Rule"));

        // When
        scanRuleRegistrar.update(statusUpdate(Status.INSTALLED, addOn));

        // Then
        assertThat(registry.getAllRules(), is(empty()));
    }

    @Test
    void shouldUnregisterRulesOfUninstalledAddOnEvenIfAlreadyRemovedFromScannersManager() {
        // Given
        AddOn addOn = addOnWithRule("Add-on", TestScanner.class);
        scanRules.add(new TestScanner(106, "Rule"));
        scanRuleRegistrar.update(statusUpdate(Status.INSTALLED, addOn));
        assertThat(registry.isRegistered(106), is(true));
        // AddOnScanRulesLoader has already removed the scanner from the manager by this point.
        scanRules.clear();

        // When
        scanRuleRegistrar.update(statusUpdate(Status.UNINSTALL, addOn));

        // Then
        assertThat(registry.isRegistered(106), is(false));
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

    private static AddOn addOnWithRule(
            String name, Class<? extends PluginPassiveScanner> ruleClass) {
        AddOn addOn = mock(AddOn.class);
        // Not every scenario reaches the logging call that reads the name, or even the add-on's
        // rule list (e.g. the registry-not-set guard), so these are lenient.
        lenient().when(addOn.getName()).thenReturn(name);
        lenient().when(addOn.getPscanrules()).thenReturn(List.of(ruleClass.getCanonicalName()));
        return addOn;
    }

    private static AddOn addOnWithNoRules(String name) {
        AddOn addOn = mock(AddOn.class);
        lenient().when(addOn.getName()).thenReturn(name);
        lenient().when(addOn.getPscanrules()).thenReturn(List.of());
        return addOn;
    }

    private static StatusUpdate statusUpdate(Status status, AddOn addOn) {
        return new StatusUpdate() {
            @Override
            public boolean isSuccessful() {
                return true;
            }

            @Override
            public Status getStatus() {
                return status;
            }

            @Override
            public AddOn getAddOn() {
                return addOn;
            }
        };
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

    private static class OtherScanner extends PluginPassiveScanner {

        private final int id;

        OtherScanner(int id) {
            this.id = id;
        }

        @Override
        public int getPluginId() {
            return id;
        }

        @Override
        public String getName() {
            return "Other";
        }
    }
}
