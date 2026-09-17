/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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
package org.zaproxy.zap.extension.scripts.scanrules;

import java.util.HashMap;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.PluginFactory;
import org.zaproxy.addon.commonlib.ExtensionCommonlib;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptWrapper;

public class ActiveScriptSynchronizer {

    private static final Logger LOGGER = LogManager.getLogger(ActiveScriptSynchronizer.class);

    private ExtensionScript extScript;
    private ExtensionCommonlib extCommonlib;
    private final Map<ScriptWrapper, ActiveScriptScanRule> scriptToScanRuleMap = new HashMap<>();

    public void scriptAdded(ScriptWrapper script) {
        try {
            ActiveScriptScanRule scanRule = scriptToScanRuleMap.get(script);

            var metadata = ScriptSynchronizerUtils.getMetadataForScript(script);
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
                    notifyGspmRuleRemoved(scanRule.getId());
                }
            }

            if (ScriptSynchronizerUtils.hasClashingId(metadata.getId(), script)) {
                return;
            }

            scanRule = new ActiveScriptScanRule(script, metadata);
            PluginFactory.loadedPlugin(scanRule);
            if (!PluginFactory.isPluginLoaded(scanRule)) {
                LOGGER.error("Failed to install script scan rule: {}", scanRule.getName());
                return;
            }
            scriptToScanRuleMap.put(script, scanRule);
            notifyGspmRuleAdded(scanRule);
        } catch (Exception e) {
            getExtScript().handleScriptException(script, e);
        }
    }

    public void scriptRemoved(ScriptWrapper script) {
        try {
            ActiveScriptScanRule scanRule = scriptToScanRuleMap.get(script);
            if (scanRule == null) {
                return;
            }
            if (unloadScanRule(scanRule)) {
                scriptToScanRuleMap.remove(script);
                notifyGspmRuleRemoved(scanRule.getId());
            }
        } catch (Exception e) {
            extScript.handleScriptException(script, e);
        }
    }

    public void unload() {
        scriptToScanRuleMap
                .values()
                .forEach(
                        scanRule -> {
                            if (unloadScanRule(scanRule)) {
                                notifyGspmRuleRemoved(scanRule.getId());
                            }
                        });
    }

    private boolean unloadScanRule(ActiveScriptScanRule scanRule) {
        PluginFactory.unloadedPlugin(scanRule);
        if (PluginFactory.isPluginLoaded(scanRule)) {
            LOGGER.error("Failed to uninstall script scan rule: {}", scanRule.getName());
            return false;
        }
        return true;
    }

    private ExtensionScript getExtScript() {
        if (extScript == null) {
            extScript =
                    Control.getSingleton().getExtensionLoader().getExtension(ExtensionScript.class);
        }
        return extScript;
    }

    /**
     * Notifies GSPM directly that this script-backed rule was added, so it shows up without waiting
     * for GSPM's initial registration or an add-on install/uninstall event.
     */
    private void notifyGspmRuleAdded(ActiveScriptScanRule scanRule) {
        ExtensionCommonlib commonlib = getExtCommonlib();
        if (commonlib != null) {
            commonlib.registerGspmActiveScanRule(scanRule);
        }
    }

    /** Notifies GSPM directly that the script-backed rule with this id was removed. */
    private void notifyGspmRuleRemoved(int id) {
        ExtensionCommonlib commonlib = getExtCommonlib();
        if (commonlib != null) {
            commonlib.unregisterGspmActiveScanRule(id);
        }
    }

    private ExtensionCommonlib getExtCommonlib() {
        if (extCommonlib == null) {
            extCommonlib =
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionCommonlib.class);
        }
        return extCommonlib;
    }
}
