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
package org.zaproxy.zap.extension.websocket.pscan;

import java.util.ArrayList;
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
import org.zaproxy.zap.extension.websocket.pscan.scripts.WebSocketPassiveScriptScanRule;

/**
 * Registers WebSocket Passive scan rules with the Global Scan Policy Manager (GSPM) in commonlib.
 *
 * <p>Rules are registered under their own {@code "wspscan"} tool key — distinct from HTTP passive
 * scan rules' {@code "pscan"}, since the two run through entirely different choke points ({@link
 * WebSocketPassiveScannerManager} vs {@code PassiveScannersManager}) and must have independent
 * registration/query/unregistration lifecycles. They still appear grouped under "Passive" in the
 * GSPM dialog, alongside {@code pscan}'s rules, via the shared {@link GspmPhase#PASSIVE} — phase is
 * a purely presentational grouping, independent of tool identity; see {@link GspmPhase}. Under that
 * phase, this tool's rules get their own {@code "WebSocket"} category, so the tree reads "Passive /
 * WebSocket". Add-on attribution isn't possible today — {@code AddOn}'s manifest schema has no
 * {@code <websocketpscanrules>} equivalent to {@code <pscanrules>}/{@code <ascanrules>} — so every
 * rule's owning add-on is always {@code null}, and {@link GspmScanRuleRegistrar}'s own
 * add-on-install-driven path contributes nothing here (see the no-op {@code rulesForAddOn} supplier
 * below).
 *
 * <p>Lifecycle: call {@link #register()} once the manager is available (from {@code postInit()}),
 * and {@link #unregister()} when the extension is unloaded. That call does a one-time bulk
 * registration of whatever is already in the {@link WebSocketPassiveScannerManager} at that point;
 * from then on, {@link #ruleAdded(WebSocketPassiveScanner)} / {@link #ruleRemoved(int)} keep GSPM
 * in sync as scanners are added to or removed from the manager (script-backed rules, or anything
 * else that calls {@code WebSocketPassiveScannerManager.add()}/{@code removeScanner()} — the single
 * choke point every WebSocket passive scan rule flows through).
 *
 * @since 39
 */
public class GspmWebSocketPassiveScanRegistrar {

    static final String TOOL = "wspscan";

    private static final String CATEGORY_WEBSOCKET_KEY = "websocket";

    private final GspmScanRuleRegistrar scanRuleRegistrar =
            new GspmScanRuleRegistrar(
                    TOOL,
                    () -> Constant.messages.getString("websocket.gspm.tool"),
                    GspmPhase.PASSIVE,
                    this::getAllCurrentRules,
                    // Add-on install/uninstall sync isn't possible for this tool yet (see class
                    // javadoc above), so there's nothing for GspmScanRuleRegistrar's own
                    // add-on-install-driven path to contribute here.
                    addOn -> List.of());

    private final WebSocketPassiveScannerManager scannersManager;
    private ExtensionCommonlib commonlib;

    public GspmWebSocketPassiveScanRegistrar(WebSocketPassiveScannerManager scannersManager) {
        this.scannersManager = scannersManager;
    }

    /**
     * Delegates registration to commonlib via {@link
     * org.zaproxy.addon.commonlib.gspm.GspmRuleSource}.
     */
    public void register() {
        commonlib =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionCommonlib.class);
        commonlib.registerGspmRuleSource(scanRuleRegistrar);
    }

    /** Unregisters all WebSocket passive scan rules from GSPM. */
    public void unregister() {
        commonlib.unregisterGspmRuleSource(scanRuleRegistrar);
    }

    /**
     * Registers a single WebSocket passive scan rule with GSPM immediately — called for every
     * scanner added to the {@link WebSocketPassiveScannerManager}, regardless of source (script or
     * anything else).
     */
    void ruleAdded(WebSocketPassiveScanner scanner) {
        scanRuleRegistrar.ruleAdded(toGspmRule(scanner));
    }

    /**
     * Unregisters a single WebSocket passive scan rule from GSPM immediately, by id — the
     * counterpart to {@link #ruleAdded(WebSocketPassiveScanner)}.
     */
    void ruleRemoved(int id) {
        scanRuleRegistrar.ruleRemoved(id);
    }

    private List<RuleOwner> getAllCurrentRules() {
        List<RuleOwner> owners = new ArrayList<>();
        for (WebSocketPassiveScanner scanner : scannersManager.getScanners()) {
            owners.add(new RuleOwner(toGspmRule(scanner), null));
        }
        return owners;
    }

    private GspmRule toGspmRule(WebSocketPassiveScanner scanner) {
        return new WebSocketGspmRule(scanner, scannersManager);
    }

    private static final class WebSocketGspmRule implements GspmRule {

        private static final List<GspmCategory> CATEGORIES =
                List.of(
                        new GspmCategory(
                                CATEGORY_WEBSOCKET_KEY,
                                Constant.messages.getString("websocket.gspm.category.websocket")));

        private final WebSocketPassiveScanner scanner;
        private final WebSocketPassiveScannerManager manager;

        WebSocketGspmRule(WebSocketPassiveScanner scanner, WebSocketPassiveScannerManager manager) {
            this.scanner = scanner;
            this.manager = manager;
        }

        @Override
        public int getId() {
            return scanner.getId();
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
            if (scanner instanceof WebSocketPassiveScriptScanRule scriptScanRule) {
                Map<String, String> tags = scriptScanRule.getAlertTags();
                return tags != null ? tags : Map.of();
            }
            return Map.of();
        }

        @Override
        public boolean isEnabled() {
            return manager.isEnabled(scanner);
        }

        @Override
        public void setEnabled(boolean enabled) {
            manager.setEnable(scanner, enabled);
        }

        @Override
        public AlertThreshold getAlertThreshold() {
            // WebSocketPassiveScanner has no threshold concept, only enabled/disabled; the
            // manager already treats OFF as the "disabled" state everywhere else, so map to that.
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
            if (scanner instanceof WebSocketPassiveScriptScanRule scriptScanRule) {
                return scriptScanRule.getStatus();
            }
            return AddOn.Status.unknown;
        }

        @Override
        public String getAddOnName() {
            return null;
        }
    }
}
