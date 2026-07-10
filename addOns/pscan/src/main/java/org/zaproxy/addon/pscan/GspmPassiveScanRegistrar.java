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

import java.util.ArrayList;
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
import org.zaproxy.zap.extension.AddOnInstallationStatusListener;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/**
 * Registers passive scan rules with the Global Scan Policy Manager (GSPM) in commonlib.
 *
 * <p>Each rule is registered under the tool key {@code "pscan"}. {@code getCategories()} returns a
 * single {@link GspmCategory} with the stable key {@code "server-side"} and an i18n display name.
 *
 * <p>Lifecycle: call {@link #register(PassiveScannersManager)} once all scan rules are loaded (from
 * {@code postInit()}), and {@link #unregister()} when the extension is unloaded. Also implements
 * {@link AddOnInstallationStatusListener} so that scan rules contributed by add-ons installed or
 * uninstalled at runtime (after the initial registration) are kept in sync with GSPM; this listener
 * must be added to the extension hook <em>after</em> the {@code AddOnScanRulesLoader} so that newly
 * installed scanners have already been added to the {@link PassiveScannersManager} by the time
 * {@link #update(StatusUpdate)} runs.
 */
class GspmPassiveScanRegistrar implements GspmRuleSource, AddOnInstallationStatusListener {

    private static final Logger LOGGER = LogManager.getLogger(GspmPassiveScanRegistrar.class);

    static final String TOOL = "pscan";

    private final Map<AddOn, List<GspmRule>> rulesByAddOn = new HashMap<>();

    private PassiveScannersManager scannersManager;
    private ExtensionCommonlib commonlib;
    private GspmRegistry registry;

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
        this.registry = registry;
        registry.registerTool(new GspmTool(TOOL, Constant.messages.getString("pscan.gspm.tool")));

        List<PluginPassiveScanner> scanRules = scannersManager.getScanRules();
        Map<PluginPassiveScanner, AddOn> addOnByScanner = buildAddOnMap(scanRules);
        int count = 0;
        for (PluginPassiveScanner scanner : scanRules) {
            if (scanner.getPluginId() == -1) {
                LOGGER.debug("GSPM: skipping passive scan rule with no ID: {}", scanner.getName());
                continue;
            }
            registerScanner(scanner, addOnByScanner.get(scanner));
            count++;
        }
        LOGGER.debug("GSPM: registered {} passive scan rules", count);
    }

    @Override
    public void unregisterRulesFromGspm(GspmRegistry registry) {
        registry.unregisterByTool(TOOL);
        rulesByAddOn.clear();
        this.registry = null;
        LOGGER.debug("GSPM: unregistered passive scan rules");
    }

    /**
     * Reacts to add-ons being installed or uninstalled while ZAP is running, keeping GSPM's view of
     * passive scan rules in sync with {@link PassiveScannersManager}.
     */
    @Override
    public void update(StatusUpdate statusUpdate) {
        switch (statusUpdate.getStatus()) {
            case INSTALLED:
                handleAddOnInstalled(statusUpdate.getAddOn());
                break;
            case SOFT_UNINSTALL:
            case UNINSTALL:
                handleAddOnUninstalled(statusUpdate.getAddOn());
                break;
            default:
        }
    }

    /**
     * Registers with GSPM any scan rules contributed by {@code addOn}, assuming they have already
     * been added to the {@link PassiveScannersManager} (e.g. by {@code AddOnScanRulesLoader}).
     */
    private void handleAddOnInstalled(AddOn addOn) {
        if (registry == null) {
            return;
        }
        List<String> pscanRuleClassNames = addOn.getPscanrules();
        if (pscanRuleClassNames.isEmpty()) {
            return;
        }
        int count = 0;
        for (PluginPassiveScanner scanner : scannersManager.getScanRules()) {
            if (scanner.getPluginId() == -1
                    || registry.isRegistered(scanner.getPluginId())
                    || !pscanRuleClassNames.contains(scanner.getClass().getCanonicalName())) {
                continue;
            }
            registerScanner(scanner, addOn);
            count++;
        }
        if (count > 0) {
            LOGGER.debug(
                    "GSPM: registered {} passive scan rules for installed add-on {}",
                    count,
                    addOn.getName());
        }
    }

    /**
     * Unregisters from GSPM the scan rules previously registered for {@code addOn}, using the rules
     * recorded at registration time rather than {@link PassiveScannersManager}, whose entries for
     * this add-on may already have been removed by the time this is called.
     */
    private void handleAddOnUninstalled(AddOn addOn) {
        if (registry == null) {
            return;
        }
        List<GspmRule> rules = rulesByAddOn.remove(addOn);
        if (rules == null || rules.isEmpty()) {
            return;
        }
        rules.forEach(registry::unregisterRule);
        LOGGER.debug(
                "GSPM: unregistered {} passive scan rules for uninstalled add-on {}",
                rules.size(),
                addOn.getName());
    }

    private void registerScanner(PluginPassiveScanner scanner, AddOn addOn) {
        GspmRule rule = new PassiveGspmRule(scanner, addOn != null ? addOn.getName() : null);
        registry.registerRule(rule);
        if (addOn != null) {
            rulesByAddOn.computeIfAbsent(addOn, a -> new ArrayList<>()).add(rule);
        }
    }

    private static Map<PluginPassiveScanner, AddOn> buildAddOnMap(
            List<PluginPassiveScanner> scanRules) {
        Map<String, AddOn> classNameToAddOn = new HashMap<>();
        try {
            for (AddOn addOn : ExtensionFactory.getAddOnLoader().getAddOnCollection().getAddOns()) {
                for (String className : addOn.getPscanrules()) {
                    classNameToAddOn.put(className, addOn);
                }
            }
        } catch (Exception e) {
            LOGGER.debug("GSPM: could not build add-on map for pscan rules", e);
        }
        Map<PluginPassiveScanner, AddOn> map = new HashMap<>();
        for (PluginPassiveScanner scanner : scanRules) {
            AddOn addOn = classNameToAddOn.get(scanner.getClass().getCanonicalName());
            if (addOn != null) {
                map.put(scanner, addOn);
            }
        }
        return map;
    }

    private static final String CATEGORY_SERVER_SIDE_KEY = "server-side";

    private static class PassiveGspmRule implements GspmRule {

        private final PluginPassiveScanner scanner;
        private final String addOnName;

        private static final List<GspmCategory> CATEGORIES =
                List.of(
                        new GspmCategory(
                                CATEGORY_SERVER_SIDE_KEY,
                                Constant.messages.getString("pscan.gspm.category.server-side")));

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
            return CATEGORIES;
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
