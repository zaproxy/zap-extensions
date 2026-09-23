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

import java.lang.reflect.UndeclaredThrowableException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Callable;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.commonlib.scanrules.ScanRuleMetadata;
import org.zaproxy.addon.commonlib.scanrules.ScanRuleMetadataProvider;
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
            new HashMap<>();

    public WebSocketScriptSynchronizer(
            ExtensionScript extScript, WebSocketPassiveScannerManager scannerManager) {
        this.extScript = extScript;
        this.scannerManager = scannerManager;
    }

    public void scriptAdded(ScriptWrapper script) {
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
            if (!scannerManager.add(scanRule)) {
                LOGGER.error("Failed to install script scan rule: {}", script.getName());
                return;
            }
            scriptToScanRuleMap.put(script, scanRule);
        } catch (Exception e) {
            extScript.handleScriptException(script, e);
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

    private boolean unloadScanRule(WebSocketPassiveScriptScanRule scanRule) {
        if (!scannerManager.removeScanner(scanRule)) {
            LOGGER.error("Failed to uninstall script scan rule: {}", scanRule.getName());
            return false;
        }
        return true;
    }

    private ScanRuleMetadata getMetadataForScript(ScriptWrapper script) throws Exception {
        var metadataProvider = extScript.getInterface(script, ScanRuleMetadataProvider.class);
        if (metadataProvider != null) {
            return callOptionalScriptMethod(metadataProvider::getMetadata);
        }
        return null;
    }

    /**
     * Calls the given method, handling exceptions thrown by some script engines when the method is
     * not defined (mirrors {@code ScriptScanRuleUtils.callOptionalScriptMethod}, not reusable here
     * as it's package-private to the {@code scripts} add-on).
     */
    private static <T> T callOptionalScriptMethod(Callable<T> method) throws Exception {
        try {
            return method.call();
        } catch (UndeclaredThrowableException ignored) {
            // Python and Kotlin scripts throw this exception when the method is not implemented
            return null;
        } catch (Exception e) {
            if (e.getCause() != null
                    && "groovy.lang.MissingMethodException"
                            .equals(e.getCause().getClass().getCanonicalName())) {
                // Groovy scripts throw this exception when the method is not implemented
                return null;
            }
            throw e;
        }
    }

    private boolean hasClashingId(int id, ScriptWrapper script) {
        for (WebSocketPassiveScanner scanner : scannerManager.getScanners()) {
            if (scanner.getId() == id) {
                String message =
                        Constant.messages.getString(
                                "websocket.pscan.scripts.duplicateId",
                                String.valueOf(id),
                                scanner.getName(),
                                script.getName());
                LOGGER.error(message);
                extScript.setError(script, message);
                extScript.setEnabled(script, false);
                return true;
            }
        }
        return false;
    }
}
