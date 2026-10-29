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
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

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
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.parosproxy.paros.core.scanner.PluginFactory;
import org.zaproxy.addon.commonlib.ExtensionCommonlib;
import org.zaproxy.addon.commonlib.gspm.GspmPolicy;
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
    private PolicyManager policyManager;

    @BeforeEach
    void setUp() throws Exception {
        GspmActiveScanRegistrar registrar = new GspmActiveScanRegistrar();
        registry = new GspmRegistry();
        plugins = new ArrayList<>();

        PolicyManager policyManager = mock(PolicyManager.class);
        ScanPolicy scanPolicy = mock(ScanPolicy.class);
        PluginFactory pluginFactory = mock(PluginFactory.class);
        lenient().when(policyManager.getTemplatePolicy()).thenReturn(scanPolicy);
        lenient().when(scanPolicy.getPluginFactory()).thenReturn(pluginFactory);
        lenient().when(pluginFactory.getAllPlugin()).thenAnswer(inv -> new ArrayList<>(plugins));

        this.policyManager = policyManager;
        setField(registrar, "policyManager", policyManager);
        scanRuleRegistrar = (GspmScanRuleRegistrar) getField(registrar, "scanRuleRegistrar");
        // Registers the tool and sets scanRuleRegistrar's registry; plugins is empty at this
        // point, so this registers zero rules.
        scanRuleRegistrar.registerRulesWithGspm(registry);
    }

    @Test
    void shouldRegisterRulesFromTemplatePolicyNotFromDefaultPolicy() throws Exception {
        // Given
        plugins.add(pluginWithId(100, "Rule A"));
        // When
        scanRuleRegistrar.registerRulesWithGspm(registry);
        // Then
        verify(policyManager, atLeastOnce()).getTemplatePolicy();
        verify(policyManager, never()).getDefaultScanPolicy();
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

    @Test
    void shouldProvidePolicyNamesAndDefaultPolicy() {
        // Given
        registry.addPolicy(new GspmPolicy("Custom"));
        // When
        List<String> names = GspmActiveScanRegistrar.getPolicyNames(registry);
        // Then
        assertThat(names.contains("Custom"), is(true));
        assertThat(GspmActiveScanRegistrar.getDefaultPolicyName(registry), is(nullValue()));
        // When
        registry.setCurrentPolicy("Custom");
        // Then
        assertThat(GspmActiveScanRegistrar.getDefaultPolicyName(registry), is("Custom"));
    }

    @Test
    void shouldLeaveRulesWithPolicyDefaultsToInheritThem() {
        // Given
        Plugin inheriting = pluginWithId(100, "Inheriting");
        Plugin overridden = pluginWithId(200, "Overridden");
        Plugin disabled = pluginWithId(300, "Disabled");
        for (Plugin plugin : List.of(inheriting, overridden, disabled)) {
            when(plugin.getAttackStrength()).thenReturn(AttackStrength.MEDIUM);
            plugins.add(plugin);
        }
        scanRuleRegistrar.registerRulesWithGspm(registry);
        GspmPolicy policy = new GspmPolicy("Custom");
        policy.findOrCreateCategoryRuleSet("all.ascan").setThresholdEnum(AlertThreshold.HIGH);
        policy.findOrCreateCategoryRuleSet("all.ascan").setStrengthEnum(AttackStrength.LOW);
        policy.setRuleThreshold(200, "Overridden", AlertThreshold.LOW);
        policy.setRuleStrength(200, "Overridden", AttackStrength.INSANE);
        policy.setRuleThreshold(300, "Disabled", AlertThreshold.OFF);
        registry.addPolicy(policy);
        PluginFactory factory = mock(PluginFactory.class);
        plugins.forEach(p -> when(factory.getPlugin(p.getId())).thenReturn(p));
        // When
        GspmActiveScanRegistrar.applyPolicy(registry, "Custom", factory);
        // Then
        verify(inheriting, never()).setAlertThreshold(any());
        verify(inheriting, never()).setAttackStrength(any());
        verify(inheriting).setEnabled(true);
        verify(overridden).setAlertThreshold(AlertThreshold.LOW);
        verify(overridden).setAttackStrength(AttackStrength.INSANE);
        verify(disabled).setAlertThreshold(AlertThreshold.OFF);
        verify(disabled).setEnabled(false);
        verify(disabled, never()).setAttackStrength(any());
    }

    @Test
    void shouldReturnSafeValuesForUnhandledMethodsOfProxy() throws Throwable {
        // Given
        Object proxy =
                java.lang.reflect.Proxy.newProxyInstance(
                        getClass().getClassLoader(),
                        new Class<?>[] {Unhandled.class},
                        (p, method, args) -> GspmActiveScanRegistrar.handleOther(p, method, args));
        Unhandled unhandled = (Unhandled) proxy;
        // When / Then
        assertThat(unhandled.flag(), is(false));
        assertThat(unhandled.number(), is(0));
        assertThat(unhandled.big(), is(0L));
        assertThat(unhandled.ratio(), is(0D));
        assertThat(unhandled.character(), is('\0'));
        assertThat(unhandled.text() == null, is(true));
        unhandled.nothing();
        assertThat(unhandled.hashCode() == System.identityHashCode(proxy), is(true));
        assertThat(unhandled.equals(proxy), is(true));
        assertThat(unhandled.equals(new Object()), is(false));
        assertThat(unhandled.defaultMethod(), is("default"));
    }

    /** Methods of an interface, like the ones that a core might add. */
    public interface Unhandled {
        boolean flag();

        int number();

        long big();

        double ratio();

        char character();

        String text();

        void nothing();

        default String defaultMethod() {
            return "default";
        }
    }

    @Test
    void shouldNotApplyUnknownPolicy() {
        // Given
        PluginFactory factory = mock(PluginFactory.class);
        // When
        boolean applied = GspmActiveScanRegistrar.applyPolicy(registry, "Unknown", factory);
        // Then
        assertThat(applied, is(false));
    }

    @Test
    void shouldApplyPolicyToPlugins() {
        // Given
        Plugin enabledRule = pluginWithId(100, "Rule A");
        when(enabledRule.getAttackStrength()).thenReturn(AttackStrength.MEDIUM);
        Plugin offRule = pluginWithId(200, "Rule B");
        plugins.add(enabledRule);
        plugins.add(offRule);
        scanRuleRegistrar.registerRulesWithGspm(registry);
        GspmPolicy policy = new GspmPolicy("Custom");
        policy.setRuleThreshold(100, "Rule A", AlertThreshold.HIGH);
        policy.setRuleStrength(100, "Rule A", AttackStrength.LOW);
        policy.setRuleThreshold(200, "Rule B", AlertThreshold.OFF);
        registry.addPolicy(policy);
        PluginFactory factory = mock(PluginFactory.class);
        when(factory.getPlugin(100)).thenReturn(enabledRule);
        when(factory.getPlugin(200)).thenReturn(offRule);
        // When
        boolean applied = GspmActiveScanRegistrar.applyPolicy(registry, "Custom", factory);
        // Then
        assertThat(applied, is(true));
        verify(enabledRule).setAlertThreshold(AlertThreshold.HIGH);
        verify(enabledRule).setEnabled(true);
        verify(enabledRule).setAttackStrength(AttackStrength.LOW);
        verify(offRule).setAlertThreshold(AlertThreshold.OFF);
        verify(offRule).setEnabled(false);
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
