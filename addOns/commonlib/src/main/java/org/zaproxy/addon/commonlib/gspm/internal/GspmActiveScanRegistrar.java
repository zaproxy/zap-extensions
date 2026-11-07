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

import java.lang.reflect.Array;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.AbstractPlugin;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.core.scanner.Plugin;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.parosproxy.paros.core.scanner.PluginFactory;
import org.zaproxy.addon.commonlib.gspm.GspmCategory;
import org.zaproxy.addon.commonlib.gspm.GspmPhase;
import org.zaproxy.addon.commonlib.gspm.GspmPolicy;
import org.zaproxy.addon.commonlib.gspm.GspmRegistry;
import org.zaproxy.addon.commonlib.gspm.GspmRule;
import org.zaproxy.addon.commonlib.gspm.GspmScanRuleRegistrar;
import org.zaproxy.addon.commonlib.gspm.GspmScanRuleRegistrar.RuleOwner;
import org.zaproxy.zap.control.AddOn;
import org.zaproxy.zap.control.ExtensionFactory;
import org.zaproxy.zap.extension.AddOnInstallationStatusListener;
import org.zaproxy.zap.extension.ascan.ExtensionActiveScan;
import org.zaproxy.zap.extension.ascan.PolicyManager;

/**
 * Registers active scan rules with the GSPM registry.
 *
 * <p>Lifecycle: call {@link #registerWithCore(GspmRegistry)} from {@code
 * ExtensionCommonlib.postInit()} and {@link #unregisterFromCore()} from {@code
 * ExtensionCommonlib.unload()}. Register {@link #getInstallationStatusListener()} with the
 * extension hook so active scan rules contributed by add-ons installed or uninstalled at runtime
 * are kept in sync with GSPM.
 */
public class GspmActiveScanRegistrar {

    private static final Logger LOGGER = LogManager.getLogger(GspmActiveScanRegistrar.class);

    private static final String PLUGABLE_POLICY_MANAGER_CLASS =
            "org.zaproxy.zap.extension.ascan.PluggableScanPolicyManager";
    private static final String REGISTER_METHOD = "registerPluggableScanPolicyManager";
    private static final String UNREGISTER_METHOD = "unregisterPluggableScanPolicyManager";

    static final String TOOL = "ascan";

    private final GspmScanRuleRegistrar scanRuleRegistrar =
            new GspmScanRuleRegistrar(
                    TOOL,
                    () -> Constant.messages.getString("commonlib.gspm.ascan.tool"),
                    GspmPhase.ACTIVE,
                    this::getAllCurrentRules,
                    this::getRulesForAddOn);

    private PolicyManager policyManager;
    private Object registeredProxy;

    /**
     * Returns the listener to register with the extension hook so that active scan rules
     * contributed by add-ons installed or uninstalled at runtime are kept in sync with GSPM.
     */
    public AddOnInstallationStatusListener getInstallationStatusListener() {
        return scanRuleRegistrar;
    }

    /**
     * Registers a {@code PluggableScanPolicyManager} proxy with {@link ExtensionActiveScan} via
     * reflection. When the core calls back, the proxy maps the call to {@link
     * GspmScanRuleRegistrar#registerRulesWithGspm} / {@link
     * GspmScanRuleRegistrar#unregisterRulesFromGspm}.
     */
    public void registerWithCore(GspmRegistry gspmRegistry) {
        registerWithCore(gspmRegistry, null);
    }

    /**
     * Same as {@link #registerWithCore(GspmRegistry)}, also providing the action that shows the
     * policy manager dialog, used by the core when the scan policies are provided by GSPM.
     *
     * @param gspmRegistry the registry.
     * @param policyManagerDisplayer the action to show the policy manager, might be {@code null}.
     */
    @SuppressWarnings("unchecked")
    public void registerWithCore(GspmRegistry gspmRegistry, Runnable policyManagerDisplayer) {
        ExtensionActiveScan extAscan =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionActiveScan.class);
        if (extAscan == null) {
            LOGGER.debug("GSPM: active scan extension not loaded, skipping registration");
            return;
        }
        // TODO register directly with core when the functionality becomes available.
        try {
            Class<?> ifaceClass = Class.forName(PLUGABLE_POLICY_MANAGER_CLASS);
            registeredProxy =
                    Proxy.newProxyInstance(
                            ifaceClass.getClassLoader(),
                            new Class<?>[] {ifaceClass},
                            (proxy, method, args) -> {
                                switch (method.getName()) {
                                    case "register":
                                        policyManager = (PolicyManager) args[0];
                                        scanRuleRegistrar.registerRulesWithGspm(gspmRegistry);
                                        break;
                                    case "unregister":
                                        scanRuleRegistrar.unregisterRulesFromGspm(gspmRegistry);
                                        break;
                                    case "getPolicyNames":
                                        return getPolicyNames(gspmRegistry);
                                    case "getDefaultPolicyName":
                                        return getDefaultPolicyName(gspmRegistry);
                                    case "applyPolicy":
                                        return applyPolicy(
                                                gspmRegistry,
                                                (String) args[0],
                                                (PluginFactory) args[1]);
                                    case "getDefaultThreshold":
                                        return GspmPolicyOperations.getDefaultThreshold(
                                                gspmRegistry, (String) args[0], TOOL);
                                    case "getDefaultStrength":
                                        return GspmPolicyOperations.getDefaultStrength(
                                                gspmRegistry, (String) args[0], TOOL);
                                    case "showPolicyManager":
                                        if (policyManagerDisplayer != null) {
                                            policyManagerDisplayer.run();
                                        }
                                        break;
                                    default:
                                        return handleOther(proxy, method, args);
                                }
                                return null;
                            });
            extAscan.getClass()
                    .getMethod(REGISTER_METHOD, ifaceClass)
                    .invoke(extAscan, registeredProxy);
            LOGGER.debug("GSPM: registered PluggableScanPolicyManager with core");
        } catch (Exception e) {
            LOGGER.debug(
                    "GSPM: PluggableScanPolicyManager not available in this zaproxy version", e);
        }
    }

    /** Gets the names of the policies, as provided to the core. */
    static List<String> getPolicyNames(GspmRegistry registry) {
        return registry.getAllPolicies().stream().map(GspmPolicy::getName).toList();
    }

    /**
     * Gets the name of the policy that the core should use by default, the current policy or the
     * built-in default one.
     */
    static String getDefaultPolicyName(GspmRegistry registry) {
        String name = registry.getCurrentPolicy();
        if (name != null) {
            return name;
        }
        name = GspmRegistry.getDefaultPolicyName();
        return registry.getPolicy(name) != null ? name : null;
    }

    /**
     * Applies the named policy to the given factory, setting the threshold, strength and enabled
     * state of the plugins that have a GSPM rule. Plugins with no rule are left as they are.
     *
     * @return {@code true} if the policy exists and was applied, {@code false} otherwise.
     */
    static boolean applyPolicy(GspmRegistry registry, String name, PluginFactory pluginFactory) {
        if (name == null || registry.getPolicy(name) == null) {
            return false;
        }
        // Rules with the policy's default are left to inherit it, so changes to the defaults of
        // the policy (e.g. by the Automation Framework) apply to them.
        AlertThreshold defaultThreshold =
                GspmPolicyOperations.getDefaultThreshold(registry, name, TOOL);
        AttackStrength defaultStrength =
                GspmPolicyOperations.getDefaultStrength(registry, name, TOOL);
        for (GspmRule rule : registry.getRulesByTool(TOOL, name)) {
            Plugin plugin = pluginFactory.getPlugin(rule.getId());
            if (plugin == null) {
                continue;
            }
            AlertThreshold threshold = rule.getAlertThreshold();
            if (threshold != null) {
                if (threshold != defaultThreshold) {
                    plugin.setAlertThreshold(threshold);
                }
                plugin.setEnabled(threshold != AlertThreshold.OFF);
            }
            AttackStrength strength = rule.getAttackStrength();
            if (strength != null && strength != defaultStrength) {
                plugin.setAttackStrength(strength);
            }
        }
        return true;
    }

    /**
     * Handles the {@code Object} methods and the interface methods not handled by this class, so
     * that the proxy never returns {@code null} for a primitive, and newer core methods (with
     * default implementations) keep their default behaviour.
     */
    static Object handleOther(Object proxy, Method method, Object[] args) throws Throwable {
        if (method.isDefault()) {
            return InvocationHandler.invokeDefault(proxy, method, args);
        }
        switch (method.getName()) {
            case "toString":
                return "GspmPluggableScanPolicyManager";
            case "hashCode":
                return System.identityHashCode(proxy);
            case "equals":
                return proxy == args[0];
            default:
                return getDefaultValue(method.getReturnType());
        }
    }

    /** Gets the value to return for the type, {@code null} unless a primitive (but void). */
    private static Object getDefaultValue(Class<?> type) {
        if (!type.isPrimitive() || type == void.class) {
            return null;
        }
        return Array.get(Array.newInstance(type, 1), 0);
    }

    /** Unregisters the proxy from {@link ExtensionActiveScan} via reflection. */
    public void unregisterFromCore() {
        if (registeredProxy == null) {
            return;
        }
        ExtensionActiveScan extAscan =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionActiveScan.class);
        if (extAscan == null) {
            return;
        }
        try {
            Class<?> ifaceClass = Class.forName(PLUGABLE_POLICY_MANAGER_CLASS);
            extAscan.getClass()
                    .getMethod(UNREGISTER_METHOD, ifaceClass)
                    .invoke(extAscan, registeredProxy);
            LOGGER.debug("GSPM: unregistered PluggableScanPolicyManager from core");
        } catch (Exception e) {
            LOGGER.debug("GSPM: failed to unregister PluggableScanPolicyManager from core", e);
        }
        registeredProxy = null;
    }

    private List<RuleOwner> getAllCurrentRules() {
        List<Plugin> plugins = getAllPlugins();
        if (plugins == null) {
            return List.of();
        }
        Map<Integer, AddOn> addOnByPluginId = buildPluginAddOnMap();
        List<RuleOwner> owners = new ArrayList<>();
        for (Plugin plugin : plugins) {
            AddOn addOn = addOnByPluginId.get(plugin.getId());
            owners.add(new RuleOwner(toGspmRule(plugin, addOn), addOn));
        }
        return owners;
    }

    private List<GspmRule> getRulesForAddOn(AddOn addOn) {
        Set<Integer> addOnPluginIds = new HashSet<>();
        for (AbstractPlugin p : addOn.getLoadedAscanrules()) {
            addOnPluginIds.add(p.getId());
        }
        if (addOnPluginIds.isEmpty()) {
            return List.of();
        }
        List<Plugin> plugins = getAllPlugins();
        if (plugins == null) {
            return List.of();
        }
        List<GspmRule> rules = new ArrayList<>();
        for (Plugin plugin : plugins) {
            if (addOnPluginIds.contains(plugin.getId())) {
                rules.add(toGspmRule(plugin, addOn));
            }
        }
        return rules;
    }

    private List<Plugin> getAllPlugins() {
        if (policyManager == null) {
            return null;
        }
        try {
            return policyManager.getTemplatePolicy().getPluginFactory().getAllPlugin();
        } catch (Exception e) {
            LOGGER.debug("GSPM: failed to get active scan plugins", e);
            return null;
        }
    }

    private static GspmRule toGspmRule(Plugin plugin, AddOn addOn) {
        return new ActiveScanGspmRule(
                plugin,
                addOn != null ? addOn.getName() : null,
                addOn != null ? addOn.getStatus() : AddOn.Status.unknown);
    }

    private static Map<Integer, AddOn> buildPluginAddOnMap() {
        Map<Integer, AddOn> map = new HashMap<>();
        try {
            for (AddOn addOn : ExtensionFactory.getAddOnLoader().getAddOnCollection().getAddOns()) {
                for (AbstractPlugin p : addOn.getLoadedAscanrules()) {
                    map.put(p.getId(), addOn);
                }
            }
        } catch (Exception e) {
            LOGGER.debug("GSPM: could not build add-on map for ascan rules", e);
        }
        return map;
    }

    @RequiredArgsConstructor
    private static final class ActiveScanGspmRule implements GspmRule {

        private final Plugin plugin;
        private final String addOnName;
        private final AddOn.Status status;

        @Override
        public int getId() {
            return plugin.getId();
        }

        @Override
        public String getName() {
            return plugin.getName();
        }

        @Override
        public String getTool() {
            return TOOL;
        }

        @Override
        public GspmPhase getPhase() {
            return GspmPhase.ACTIVE;
        }

        @Override
        public List<GspmCategory> getCategories() {
            return List.of(
                    new GspmCategory(
                            categoryKey(plugin.getCategory()),
                            Category.getName(plugin.getCategory())));
        }

        @Override
        public Map<String, String> getAlertTags() {
            return plugin.getAlertTags();
        }

        @Override
        public boolean isEnabled() {
            return plugin.isEnabled();
        }

        @Override
        public void setEnabled(boolean enabled) {
            plugin.setEnabled(enabled);
        }

        @Override
        public AlertThreshold getAlertThreshold() {
            return plugin.getAlertThreshold();
        }

        @Override
        public void setAlertThreshold(AlertThreshold threshold) {
            plugin.setAlertThreshold(threshold);
        }

        @Override
        public AttackStrength getAttackStrength() {
            return plugin.getAttackStrength();
        }

        @Override
        public void setAttackStrength(AttackStrength strength) {
            plugin.setAttackStrength(strength);
        }

        @Override
        public AddOn.Status getStatus() {
            return status;
        }

        @Override
        public String getAddOnName() {
            return addOnName;
        }
    }

    static String categoryKey(int category) {
        return switch (category) {
            case Category.INFO_GATHER -> "info";
            case Category.BROWSER -> "browser";
            case Category.SERVER -> "server";
            case Category.MISC -> "misc";
            case Category.INJECTION -> "inject";
            default -> "undefined";
        };
    }
}
