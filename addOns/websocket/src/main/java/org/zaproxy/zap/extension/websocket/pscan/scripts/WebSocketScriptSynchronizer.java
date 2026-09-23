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
package org.zaproxy.zap.extension.websocket.pscan.scripts;

import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.zaproxy.addon.commonlib.ExtensionCommonlib;
import org.zaproxy.addon.commonlib.gspm.GspmRegistry;
import org.zaproxy.addon.commonlib.gspm.GspmRule;
import org.zaproxy.addon.commonlib.scanrules.ScanRuleMetadata;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.websocket.pscan.WebSocketPassiveScanner;
import org.zaproxy.zap.extension.websocket.pscan.WebSocketPassiveScannerManager;

/**
 * Keeps {@link WebSocketPassiveScannerManager} in sync with WebSocket Passive Rule scripts that
 * declare {@link ScanRuleMetadata}, mirroring {@code PassiveScriptSynchronizer} in the {@code
 * scripts} add-on.
 */
public class WebSocketScriptSynchronizer {

    private static final Logger LOGGER = LogManager.getLogger(WebSocketScriptSynchronizer.class);

    private final ExtensionScript extScript;
    private final WebSocketPassiveScannerManager scannerManager;
    private final Map<ScriptWrapper, WebSocketPassiveScriptScanRule> scriptToScanRuleMap =
            new ConcurrentHashMap<>();
    private final Set<ScriptWrapper> scriptsBeingProcessed = ConcurrentHashMap.newKeySet();

    public WebSocketScriptSynchronizer(
            ExtensionScript extScript, WebSocketPassiveScannerManager scannerManager) {
        this.extScript = extScript;
        this.scannerManager = scannerManager;
    }

    public void scriptAdded(ScriptWrapper script) {
        if (!scriptsBeingProcessed.add(script)) {
            // Already being processed higher up the call stack, e.g. disabling the script below
            // triggers a script changed event which re-enters this method for the same script.
            return;
        }
        try {
            WebSocketPassiveScriptScanRule scanRule = scriptToScanRuleMap.get(script);

            ScanRuleMetadata metadata = getMetadataForScript(script);
            if (metadata == null) {
                if (scanRule != null) {
                    // The metadata function was removed from the script
                    scriptRemoved(script);
                }
                return;
            }

            if (scanRule != null) {
                if (scanRule.getId() == metadata.getId()) {
                    scanRule.setMetadata(metadata);
                    return;
                }
                if (unloadScanRule(scanRule)) {
                    scriptToScanRuleMap.remove(script);
                }
            }

            if (hasClashingId(metadata.getId(), script)) {
                return;
            }

            scanRule = new WebSocketPassiveScriptScanRule(script, metadata);
            scriptToScanRuleMap.put(script, scanRule);
            if (!scannerManager.add(scanRule)) {
                scriptToScanRuleMap.remove(script);
                LOGGER.error(
                        "Failed to install script scan rule: {} Id {} ",
                        script.getName(),
                        metadata.getId());
                return;
            }
        } catch (Exception e) {
            extScript.handleScriptException(script, e);
        } finally {
            scriptsBeingProcessed.remove(script);
        }
    }

    public void scriptRemoved(ScriptWrapper script) {
        try {
            WebSocketPassiveScriptScanRule scanRule = scriptToScanRuleMap.get(script);
            if (scanRule == null) {
                return;
            }
            if (unloadScanRule(scanRule)) {
                scriptToScanRuleMap.remove(script);
            }
        } catch (Exception e) {
            extScript.handleScriptException(script, e);
        }
    }

    public void unload() {
        scriptToScanRuleMap.values().forEach(this::unloadScanRule);
    }

    /**
     * Tells whether the given script currently has its own synchronized {@link
     * WebSocketPassiveScriptScanRule} installed — {@code false} if it declares no metadata, or if
     * synchronization was attempted but failed (e.g. a clashing id), in which case it must not be
     * excluded from {@link ScriptsWebSocketPassiveScanner}'s legacy execution path.
     */
    public boolean isSynchronized(ScriptWrapper script) {
        return scriptToScanRuleMap.containsKey(script);
    }

    private boolean unloadScanRule(WebSocketPassiveScriptScanRule scanRule) {
        if (!scannerManager.removeScanner(scanRule)) {
            LOGGER.error("Failed to uninstall script scan rule: {}", scanRule.getName());
            return false;
        }
        return true;
    }

    private ScanRuleMetadata getMetadataForScript(ScriptWrapper script) throws Exception {
        return WebSocketScriptMetadataUtils.getMetadata(extScript, script);
    }

    private boolean hasClashingId(int id, ScriptWrapper script) {
        for (WebSocketPassiveScanner scanner : scannerManager.getScanners()) {
            if (scanner.getId() == id) {
                reportClashingId(id, scanner.getName(), script);
                return true;
            }
        }

        // GSPM rule ids must be unique across every tool (active scan, HTTP passive scan, other
        // WebSocket passive scanners, ...), not just this manager's own scanners, otherwise
        // GspmRegistry#registerRule throws once scannerManager.add() below tries to register it.
        GspmRegistry gspmRegistry = getGspmRegistry();
        if (gspmRegistry != null) {
            Optional<GspmRule> clashingRule = gspmRegistry.getRule(id);
            if (clashingRule.isPresent()) {
                reportClashingId(id, clashingRule.get().getName(), script);
                return true;
            }
        }
        return false;
    }

    private void reportClashingId(int id, String existingRuleName, ScriptWrapper script) {
        String message =
                Constant.messages.getString(
                        "websocket.pscan.scripts.duplicateId",
                        String.valueOf(id),
                        existingRuleName,
                        script.getName());
        LOGGER.error(message);
        extScript.setError(script, message);
        extScript.setEnabled(script, false);
    }

    private static GspmRegistry getGspmRegistry() {
        Control control = Control.getSingleton();
        if (control == null) {
            return null;
        }
        ExtensionCommonlib commonlib =
                control.getExtensionLoader().getExtension(ExtensionCommonlib.class);
        return commonlib != null ? commonlib.getGspmRegistry() : null;
    }
}
