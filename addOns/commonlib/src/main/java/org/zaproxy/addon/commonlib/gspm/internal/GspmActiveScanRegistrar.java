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
import org.zaproxy.addon.commonlib.gspm.GspmCategory;
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
                                    default:
                                        break;
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
            return policyManager.getDefaultScanPolicy().getPluginFactory().getAllPlugin();
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

    private static String categoryKey(int category) {
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
