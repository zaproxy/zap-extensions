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

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.zaproxy.addon.commonlib.ExtensionCommonlib;
import org.zaproxy.addon.commonlib.gspm.GspmCategory;
import org.zaproxy.addon.commonlib.gspm.GspmRegistry;
import org.zaproxy.addon.commonlib.gspm.GspmRule;
import org.zaproxy.addon.commonlib.gspm.GspmRuleSource;
import org.zaproxy.addon.commonlib.gspm.GspmTool;
import org.zaproxy.zap.control.AddOn;
import org.zaproxy.zap.control.ExtensionFactory;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/**
 * Registers passive scan rules with the Global Scan Policy Manager (GSPM) in commonlib.
 *
 * <p>Each rule is registered under the tool key {@code "pscan"}. {@code getCategories()} returns a
 * single {@link GspmCategory} with the stable key {@code "server-side"} and an i18n display name.
 *
 * <p>Unlike the active scan case in zaproxy core, pscan has a compile-time dependency on commonlib
 * so no reflection is needed here.
 *
 * <p>Lifecycle: call {@link #register(PassiveScannersManager)} once all scan rules are loaded (from
 * {@code postInit()}), and {@link #unregister()} when the extension is unloaded.
 */
class GspmPassiveScanRegistrar implements GspmRuleSource {

    private static final Logger LOGGER = LogManager.getLogger(GspmPassiveScanRegistrar.class);

    static final String TOOL = "pscan";

    private PassiveScannersManager scannersManager;
    private ExtensionCommonlib commonlib;

    /**
     * Stores the scanners manager and delegates registration to commonlib via {@link
     * GspmRuleSource}.
     */
    void register(PassiveScannersManager scannersManager) {
        this.scannersManager = scannersManager;
        commonlib =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionCommonlib.class);
        commonlib.registerGspmRuleSource(this);
    }

    /** Unregisters all passive scan rules from GSPM. */
    void unregister() {
        commonlib.unregisterGspmRuleSource(this);
    }

    @Override
    public void registerRulesWithGspm(GspmRegistry registry) {
        registry.registerTool(new GspmTool(TOOL, Constant.messages.getString("pscan.gspm.tool")));

        List<PluginPassiveScanner> scanRules = scannersManager.getScanRules();
        Map<PluginPassiveScanner, String> addOnNames = buildAddOnNameMap(scanRules);
        int count = 0;
        for (PluginPassiveScanner scanner : scanRules) {
            if (scanner.getPluginId() == -1) {
                LOGGER.debug("GSPM: skipping passive scan rule with no ID: {}", scanner.getName());
                continue;
            }
            registry.registerRule(new PassiveGspmRule(scanner, addOnNames.get(scanner)));
            count++;
        }
        LOGGER.debug("GSPM: registered {} passive scan rules", count);
    }

    @Override
    public void unregisterRulesFromGspm(GspmRegistry registry) {
        registry.unregisterByTool(TOOL);
        LOGGER.debug("GSPM: unregistered passive scan rules");
    }

    private static Map<PluginPassiveScanner, String> buildAddOnNameMap(
            List<PluginPassiveScanner> scanRules) {
        Map<String, String> classNameToAddOn = new HashMap<>();
        try {
            for (AddOn addOn : ExtensionFactory.getAddOnLoader().getAddOnCollection().getAddOns()) {
                String name = addOn.getName();
                for (String className : addOn.getPscanrules()) {
                    classNameToAddOn.put(className, name);
                }
            }
        } catch (Exception e) {
            LOGGER.debug("GSPM: could not build add-on name map for pscan rules", e);
        }
        Map<PluginPassiveScanner, String> map = new HashMap<>();
        for (PluginPassiveScanner scanner : scanRules) {
            String addOnName = classNameToAddOn.get(scanner.getClass().getCanonicalName());
            if (addOnName != null) {
                map.put(scanner, addOnName);
            }
        }
        return map;
    }

    private static final String CATEGORY_SERVER_SIDE_KEY = "server-side";

    private static class PassiveGspmRule implements GspmRule {

        private final PluginPassiveScanner scanner;
        private final String addOnName;

        PassiveGspmRule(PluginPassiveScanner scanner, String addOnName) {
            this.scanner = scanner;
            this.addOnName = addOnName;
        }

        @Override
        public int getId() {
            return scanner.getPluginId();
        }

        @Override
        public String getName() {
            return scanner.getName();
        }

        @Override
        public String getTool() {
            return TOOL;
        }

        @Override
        public List<GspmCategory> getCategories() {
            return List.of(
                    new GspmCategory(
                            CATEGORY_SERVER_SIDE_KEY,
                            Constant.messages.getString("pscan.gspm.category.server-side")));
        }

        @Override
        public Map<String, String> getAlertTags() {
            Map<String, String> tags = scanner.getAlertTags();
            return tags != null ? tags : Map.of();
        }

        @Override
        public boolean isEnabled() {
            return scanner.isEnabled();
        }

        @Override
        public void setEnabled(boolean enabled) {
            scanner.setEnabled(enabled);
        }

        @Override
        public AlertThreshold getAlertThreshold() {
            return scanner.getAlertThreshold();
        }

        @Override
        public void setAlertThreshold(AlertThreshold threshold) {
            scanner.setAlertThreshold(threshold);
        }

        @Override
        public AttackStrength getAttackStrength() {
            return null;
        }

        @Override
        public void setAttackStrength(AttackStrength strength) {
            // no-op: passive rules do not have attack strength
        }

        @Override
        public AddOn.Status getStatus() {
            return scanner.getStatus();
        }

        @Override
        public String getAddOnName() {
            return addOnName;
        }
    }
}
