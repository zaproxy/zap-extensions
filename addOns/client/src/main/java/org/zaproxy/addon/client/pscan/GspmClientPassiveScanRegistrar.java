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
package org.zaproxy.addon.client.pscan;

import java.util.List;
import java.util.Map;
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

/**
 * Registers the client passive scan rules with the Global Scan Policy Manager (GSPM) in commonlib.
 *
 * <p>Client passive scan rules only support being enabled or disabled, so the alert threshold is
 * mapped to {@link AlertThreshold#MEDIUM} (enabled) or {@link AlertThreshold#OFF} (disabled).
 */
public class GspmClientPassiveScanRegistrar {

    static final String TOOL = "clientpscan";

    private static final List<GspmCategory> CATEGORIES =
            List.of(
                    new GspmCategory(
                            "client", Constant.messages.getString("client.gspm.category")));

    private final ClientPassiveScanController controller;
    private final AddOn addOn;

    private final GspmScanRuleRegistrar scanRuleRegistrar =
            new GspmScanRuleRegistrar(
                    TOOL,
                    () -> Constant.messages.getString("client.gspm.tool"),
                    GspmPhase.PASSIVE,
                    this::getAllCurrentRules,
                    addOn -> List.of());

    private ExtensionCommonlib commonlib;

    /**
     * @param controller the controller holding the rules
     * @param addOn the add-on providing the rules, used for their status and add-on name
     */
    public GspmClientPassiveScanRegistrar(ClientPassiveScanController controller, AddOn addOn) {
        this.controller = controller;
        this.addOn = addOn;
    }

    public void register() {
        commonlib =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionCommonlib.class);
        commonlib.registerGspmRuleSource(scanRuleRegistrar);
    }

    public void unregister() {
        if (commonlib != null) {
            commonlib.unregisterGspmRuleSource(scanRuleRegistrar);
        }
    }

    private List<RuleOwner> getAllCurrentRules() {
        return controller.getAllScanRules().stream()
                .map(r -> new RuleOwner(new ClientGspmRule(r, addOn), addOn))
                .toList();
    }

    /** A GSPM view of a client passive scan rule. */
    private record ClientGspmRule(ClientPassiveScanRule rule, AddOn addOn) implements GspmRule {

        @Override
        public int getId() {
            return rule.getId();
        }

        @Override
        public String getName() {
            return rule.getName();
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
            return Map.of();
        }

        @Override
        public boolean isEnabled() {
            return rule.isEnabled();
        }

        @Override
        public void setEnabled(boolean enabled) {
            rule.setEnabled(enabled);
        }

        @Override
        public AlertThreshold getAlertThreshold() {
            return isEnabled() ? AlertThreshold.MEDIUM : AlertThreshold.OFF;
        }

        @Override
        public void setAlertThreshold(AlertThreshold threshold) {
            setEnabled(threshold != null && threshold != AlertThreshold.OFF);
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
            return addOn != null ? addOn.getStatus() : AddOn.Status.unknown;
        }

        @Override
        public String getAddOnName() {
            return addOn != null ? addOn.getName() : null;
        }
    }
}
