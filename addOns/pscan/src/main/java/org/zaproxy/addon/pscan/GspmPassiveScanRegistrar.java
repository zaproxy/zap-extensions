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
import org.zaproxy.addon.commonlib.gspm.GspmPhase;
import org.zaproxy.addon.commonlib.gspm.GspmRule;
import org.zaproxy.addon.commonlib.gspm.GspmScanRuleRegistrar;
import org.zaproxy.addon.commonlib.gspm.GspmScanRuleRegistrar.RuleOwner;
import org.zaproxy.zap.control.AddOn;
import org.zaproxy.zap.control.ExtensionFactory;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/**
 * Registers passive scan rules with the Global Scan Policy Manager (GSPM) in commonlib.
 *
 * <p>Each rule is registered under the tool key {@code "pscan"}. {@code getCategories()} returns a
 * single {@link GspmCategory} with the stable key {@code "server-side"} and an i18n display name.
 *
 * <p>Lifecycle: call {@link #register(PassiveScannersManager)} once all scan rules are loaded (from
 * {@code postInit()}), and {@link #unregister()} when the extension is unloaded. That call does a
 * one-time bulk registration of whatever is already in the {@link PassiveScannersManager} at that
 * point; from then on, {@link #ruleAdded(PluginPassiveScanner)} / {@link #ruleRemoved(int)} keep
 * GSPM in sync as rules are added to or removed from the manager (add-on install/uninstall,
 * script-backed rules, or anything else that calls {@code PassiveScannersManager.add()}/{@code
 * .remove()} — see {@code ExtensionPassiveScan2.PassiveScannersManagerImpl}, the single choke point
 * every passive scan rule flows through).
 */
class GspmPassiveScanRegistrar {

    private static final Logger LOGGER = LogManager.getLogger(GspmPassiveScanRegistrar.class);

    static final String TOOL = "pscan";

    private final GspmScanRuleRegistrar scanRuleRegistrar =
            new GspmScanRuleRegistrar(
                    TOOL,
                    () -> Constant.messages.getString("pscan.gspm.tool"),
                    GspmPhase.PASSIVE,
                    this::getAllCurrentRules,
                    // Add-on install/uninstall sync happens via ruleAdded/ruleRemoved instead (see
                    // class javadoc above), so there's nothing for GspmScanRuleRegistrar's own
                    // add-on-install-driven path to contribute here.
                    addOn -> List.of());

    private final PassiveScannersManager scannersManager;
    private ExtensionCommonlib commonlib;

    public GspmPassiveScanRegistrar(PassiveScannersManager scannersManager) {
        this.scannersManager = scannersManager;
    }

    /**
     * Delegates registration to commonlib via {@link
     * org.zaproxy.addon.commonlib.gspm.GspmRuleSource}.
     */
    void register() {
        commonlib =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionCommonlib.class);
        commonlib.registerGspmRuleSource(scanRuleRegistrar);
    }

    /** Unregisters all passive scan rules from GSPM. */
    void unregister() {
        commonlib.unregisterGspmRuleSource(scanRuleRegistrar);
    }

    /**
     * Registers a single passive scan rule with GSPM immediately — called for every rule added to
     * the {@link PassiveScannersManager}, regardless of source (add-on install, script, or anything
     * else).
     */
    void ruleAdded(PluginPassiveScanner scanner) {
        if (scanner.getPluginId() == -1) {
            LOGGER.debug("GSPM: skipping passive scan rule with no ID: {}", scanner.getName());
            return;
        }
        scanRuleRegistrar.ruleAdded(toGspmRule(scanner, findOwningAddOn(scanner)));
    }

    /**
     * Unregisters a single passive scan rule from GSPM immediately, by id — the counterpart to
     * {@link #ruleAdded(PluginPassiveScanner)}.
     */
    void ruleRemoved(int id) {
        scanRuleRegistrar.ruleRemoved(id);
    }

    private List<RuleOwner> getAllCurrentRules() {
        List<PluginPassiveScanner> scanRules = scannersManager.getScanRules();
        Map<PluginPassiveScanner, AddOn> addOnByScanner = buildAddOnMap(scanRules);
        List<RuleOwner> owners = new ArrayList<>();
        for (PluginPassiveScanner scanner : scanRules) {
            if (scanner.getPluginId() == -1) {
                LOGGER.debug("GSPM: skipping passive scan rule with no ID: {}", scanner.getName());
                continue;
            }
            AddOn addOn = addOnByScanner.get(scanner);
            owners.add(new RuleOwner(toGspmRule(scanner, addOn), addOn));
        }
        return owners;
    }

    private static GspmRule toGspmRule(PluginPassiveScanner scanner, AddOn addOn) {
        return new PassiveGspmRule(scanner, addOn != null ? addOn.getName() : null);
    }

    /**
     * Looks up the add-on that contributes {@code scanner}, by matching its class name against
     * every installed add-on's declared {@code pscanrules} list. {@code null} if none matches (e.g.
     * a script-backed rule, which isn't contributed by an add-on).
     */
    private static AddOn findOwningAddOn(PluginPassiveScanner scanner) {
        try {
            return findOwningAddOn(
                    scanner, ExtensionFactory.getAddOnLoader().getAddOnCollection().getAddOns());
        } catch (Exception e) {
            LOGGER.debug(
                    "GSPM: could not determine owning add-on for pscan rule {}",
                    scanner.getClass().getCanonicalName(),
                    e);
            return null;
        }
    }

    /**
     * Pure matching logic behind {@link #findOwningAddOn(PluginPassiveScanner)}, split out so it
     * can be unit tested without needing to fake {@link ExtensionFactory}'s static add-on loader.
     */
    static AddOn findOwningAddOn(PluginPassiveScanner scanner, List<AddOn> addOns) {
        String className = scanner.getClass().getCanonicalName();
        for (AddOn addOn : addOns) {
            if (addOn.getPscanrules().contains(className)) {
                return addOn;
            }
        }
        return null;
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
        public GspmPhase getPhase() {
            return GspmPhase.PASSIVE;
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
