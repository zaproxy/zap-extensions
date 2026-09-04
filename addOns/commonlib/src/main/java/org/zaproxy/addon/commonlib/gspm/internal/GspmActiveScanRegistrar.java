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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
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
import org.zaproxy.addon.commonlib.gspm.GspmRuleSource;
import org.zaproxy.addon.commonlib.gspm.GspmTool;
import org.zaproxy.zap.control.AddOn;
import org.zaproxy.zap.control.ExtensionFactory;
import org.zaproxy.zap.extension.ascan.ExtensionActiveScan;
import org.zaproxy.zap.extension.ascan.PolicyManager;

/**
 * Registers active scan rules with the GSPM registry.
 *
 * <p>Registers itself with zaproxy core via the {@code PluggableScanPolicyManager} extension point,
 * using reflection because that interface is not yet in the released zaproxy jar. When the core
 * calls back, it maps the call to the {@link GspmRuleSource} methods.
 *
 * <p>Lifecycle: call {@link #registerWithCore(GspmRegistry)} from {@code
 * ExtensionCommonlib.postInit()} and {@link #unregisterFromCore()} from {@code
 * ExtensionCommonlib.unload()}.
 */
public class GspmActiveScanRegistrar implements GspmRuleSource {

    private static final Logger LOGGER = LogManager.getLogger(GspmActiveScanRegistrar.class);

    private static final String PLUGABLE_POLICY_MANAGER_CLASS =
            "org.zaproxy.zap.extension.ascan.PluggableScanPolicyManager";
    private static final String REGISTER_METHOD = "registerPluggableScanPolicyManager";
    private static final String UNREGISTER_METHOD = "unregisterPluggableScanPolicyManager";

    static final String TOOL = "ascan";

    private GspmRegistry registry;
    private PolicyManager policyManager;
    private Object registeredProxy;

    /**
     * Registers a {@code PluggableScanPolicyManager} proxy with {@link ExtensionActiveScan} via
     * reflection. When the core calls back, the proxy maps the call to {@link
     * GspmRuleSource#registerRulesWithGspm} / {@link GspmRuleSource#unregisterRulesFromGspm}.
     */
    public void registerWithCore(GspmRegistry gspmRegistry) {
        this.registry = gspmRegistry;
        ExtensionActiveScan extAscan =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionActiveScan.class);
        if (extAscan == null) {
            LOGGER.debug("GSPM: active scan extension not loaded, skipping registration");
            return;
        }
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
                                        registerRulesWithGspm(registry);
                                        break;
                                    case "unregister":
                                        unregisterRulesFromGspm(registry);
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

    @Override
    public void registerRulesWithGspm(GspmRegistry reg) {
        if (policyManager == null) {
            return;
        }
        reg.registerTool(
                new GspmTool(TOOL, Constant.messages.getString("commonlib.gspm.ascan.tool")));
        List<Plugin> plugins;
        try {
            plugins = policyManager.getDefaultScanPolicy().getPluginFactory().getAllPlugin();
        } catch (Exception e) {
            LOGGER.debug("GSPM: failed to get active scan plugins", e);
            return;
        }
        Map<Integer, AddOn> addOnByPluginId = buildPluginAddOnMap();
        for (Plugin plugin : plugins) {
            AddOn addOn = addOnByPluginId.get(plugin.getId());
            reg.registerRule(
                    new ActiveScanGspmRule(
                            plugin,
                            addOn != null ? addOn.getName() : null,
                            addOn != null ? addOn.getStatus() : AddOn.Status.unknown));
        }
        LOGGER.debug("GSPM: registered {} active scan rules", plugins.size());
    }

    @Override
    public void unregisterRulesFromGspm(GspmRegistry reg) {
        reg.unregisterByTool(TOOL);
        LOGGER.debug("GSPM: unregistered active scan rules");
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

    private static final class ActiveScanGspmRule implements GspmRule {

        private final Plugin plugin;
        private final String addOnName;
        private final AddOn.Status status;

        ActiveScanGspmRule(Plugin plugin, String addOnName, AddOn.Status status) {
            this.plugin = plugin;
            this.addOnName = addOnName;
            this.status = status;
        }

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
