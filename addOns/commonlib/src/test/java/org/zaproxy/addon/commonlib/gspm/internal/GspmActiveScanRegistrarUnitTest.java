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
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractPlugin;
import org.parosproxy.paros.core.scanner.Plugin;
import org.parosproxy.paros.core.scanner.PluginFactory;
import org.zaproxy.addon.commonlib.ExtensionCommonlib;
import org.zaproxy.addon.commonlib.gspm.GspmRegistry;
import org.zaproxy.addon.commonlib.gspm.GspmRule;
import org.zaproxy.addon.commonlib.gspm.GspmScanRuleRegistrar;
import org.zaproxy.zap.control.AddOn;
import org.zaproxy.zap.extension.AddOnInstallationStatusListener.StatusUpdate;
import org.zaproxy.zap.extension.AddOnInstallationStatusListener.StatusUpdate.Status;
import org.zaproxy.zap.extension.ascan.PolicyManager;
import org.zaproxy.zap.extension.ascan.ScanPolicy;
import org.zaproxy.zap.testutils.TestUtils;

/**
 * Unit test for {@link GspmActiveScanRegistrar}, focused on how it maps active scan plugins to
 * {@link GspmRule}s and matches them to add-ons. The generic add-on install/uninstall bookkeeping
 * it delegates to is covered by {@code GspmScanRuleRegistrarUnitTest}.
 */
class GspmActiveScanRegistrarUnitTest extends TestUtils {

    @BeforeAll
    static void setupMessages() {
        // PolicyManager's static initializer reads Constant.messages, so it must be non-null
        // before Mockito can even load/instrument the class for mocking.
        mockMessages(new ExtensionCommonlib());
    }

    @AfterAll
    static void cleanUp() {
        Constant.messages = null;
    }

    private GspmScanRuleRegistrar scanRuleRegistrar;
    private GspmRegistry registry;
    private List<Plugin> plugins;

    @BeforeEach
    void setUp() throws Exception {
        GspmActiveScanRegistrar registrar = new GspmActiveScanRegistrar();
        registry = new GspmRegistry();
        plugins = new ArrayList<>();

        PolicyManager policyManager = mock(PolicyManager.class);
        ScanPolicy scanPolicy = mock(ScanPolicy.class);
        PluginFactory pluginFactory = mock(PluginFactory.class);
        lenient().when(policyManager.getDefaultScanPolicy()).thenReturn(scanPolicy);
        lenient().when(scanPolicy.getPluginFactory()).thenReturn(pluginFactory);
        lenient().when(pluginFactory.getAllPlugin()).thenAnswer(inv -> new ArrayList<>(plugins));

        setField(registrar, "policyManager", policyManager);
        scanRuleRegistrar = (GspmScanRuleRegistrar) getField(registrar, "scanRuleRegistrar");
        // Registers the tool and sets scanRuleRegistrar's registry; plugins is empty at this
        // point, so this registers zero rules.
        scanRuleRegistrar.registerRulesWithGspm(registry);
    }

    @Test
    void shouldRegisterAllPluginsOnInitialRegistration() {
        // Given — add-on attribution during the initial load comes from ExtensionFactory's
        // add-on loader, which isn't set up in this unit test context, so both plugins are
        // registered without an owning add-on here; that attribution is exercised instead by
        // the install-time tests below, which supply the add-on directly.
        plugins.add(pluginWithId(100, "Rule A"));
        plugins.add(pluginWithId(200, "Rule B"));

        // When
        scanRuleRegistrar.registerRulesWithGspm(registry);

        // Then
        List<GspmRule> rules = registry.getRulesByTool(GspmActiveScanRegistrar.TOOL);
        assertThat(rules, hasSize(2));
        assertThat(rules.stream().map(GspmRule::getId).toList(), containsInAnyOrder(100, 200));
    }

    @Test
    void shouldRegisterPluginAddedForInstalledAddOn() {
        // Given
        AddOn addOn = addOnWithRule("Extra Add-on", 101);
        plugins.add(pluginWithId(101, "Extra Rule"));

        // When
        scanRuleRegistrar.update(statusUpdate(Status.INSTALLED, addOn));

        // Then
        assertThat(registry.isRegistered(101), is(true));
        List<GspmRule> rules = registry.getRulesByTool(GspmActiveScanRegistrar.TOOL);
        assertThat(rules, hasSize(1));
        assertThat(rules.get(0).getId(), is(101));
        assertThat(rules.get(0).getAddOnName(), is("Extra Add-on"));
    }

    @Test
    void shouldIgnorePluginsNotBelongingToInstalledAddOn() {
        // Given
        AddOn addOn = addOnWithRule("Extra Add-on", 101);
        plugins.add(pluginWithId(102, "Other Rule"));

        // When
        scanRuleRegistrar.update(statusUpdate(Status.INSTALLED, addOn));

        // Then
        assertThat(registry.getAllRules(), is(empty()));
    }

    @Test
    void shouldDoNothingWhenInstalledAddOnHasNoAscanRules() {
        // Given
        AddOn addOn = addOnWithNoRules("Add-on");
        plugins.add(pluginWithId(104, "Rule"));

        // When
        scanRuleRegistrar.update(statusUpdate(Status.INSTALLED, addOn));

        // Then
        assertThat(registry.getAllRules(), is(empty()));
    }

    @Test
    void shouldUnregisterRulesOfUninstalledAddOnEvenIfAlreadyRemovedFromPluginFactory() {
        // Given
        AddOn addOn = addOnWithRule("Add-on", 106);
        plugins.add(pluginWithId(106, "Rule"));
        scanRuleRegistrar.update(statusUpdate(Status.INSTALLED, addOn));
        assertThat(registry.isRegistered(106), is(true));
        // Core add-on uninstall handling has already removed the plugin by this point.
        plugins.clear();

        // When
        scanRuleRegistrar.update(statusUpdate(Status.UNINSTALL, addOn));

        // Then
        assertThat(registry.isRegistered(106), is(false));
        assertThat(registry.getAllRules(), is(empty()));
    }

    private static void setField(GspmActiveScanRegistrar target, String name, Object value)
            throws Exception {
        Field field = GspmActiveScanRegistrar.class.getDeclaredField(name);
        field.setAccessible(true);
        field.set(target, value);
    }

    private static Object getField(GspmActiveScanRegistrar target, String name) throws Exception {
        Field field = GspmActiveScanRegistrar.class.getDeclaredField(name);
        field.setAccessible(true);
        return field.get(target);
    }

    private static AddOn addOnWithRule(String name, int pluginId) {
        AddOn addOn = mock(AddOn.class);
        AbstractPlugin plugin = mock(AbstractPlugin.class);
        // Not every scenario reaches the logging call that reads the name, or even the add-on's
        // rule list (e.g. the registry-not-set guard), so these are lenient.
        lenient().when(addOn.getName()).thenReturn(name);
        lenient().when(plugin.getId()).thenReturn(pluginId);
        lenient().when(addOn.getLoadedAscanrules()).thenReturn(List.of(plugin));
        return addOn;
    }

    private static AddOn addOnWithNoRules(String name) {
        AddOn addOn = mock(AddOn.class);
        lenient().when(addOn.getName()).thenReturn(name);
        lenient().when(addOn.getLoadedAscanrules()).thenReturn(List.of());
        return addOn;
    }

    private static Plugin pluginWithId(int id, String name) {
        Plugin plugin = mock(Plugin.class);
        lenient().when(plugin.getId()).thenReturn(id);
        lenient().when(plugin.getName()).thenReturn(name);
        return plugin;
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
}
