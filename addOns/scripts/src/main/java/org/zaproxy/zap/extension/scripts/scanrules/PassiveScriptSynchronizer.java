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
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.dynamic.loading.ClassLoadingStrategy;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.control.Control;
import org.zaproxy.zap.extension.pscan.ExtensionPassiveScan;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptWrapper;

public class PassiveScriptSynchronizer {

    private static final Logger LOGGER = LogManager.getLogger(PassiveScriptSynchronizer.class);

    private ExtensionScript extScript;
    private ExtensionPassiveScan extPscan;

    private final Map<ScriptWrapper, PassiveScriptScanRule> scriptToScanRuleMap = new HashMap<>();

    public void scriptAdded(ScriptWrapper script) {
        try {
            PassiveScriptScanRule scanRule = scriptToScanRuleMap.get(script);

            var metadata = ScriptSynchronizerUtils.getMetadataForScript(script);
            if (metadata == null) {
                if (scanRule != null) {
                    // The metadata function was removed from the script
                    scriptRemoved(script);
                }
                return;
            }

            if (scanRule != null) {
                if (scanRule.getPluginId() == metadata.getId()) {
                    scanRule.setMetadata(metadata);
                    return;
                }
                if (unloadScanRule(scanRule)) {
                    scriptToScanRuleMap.remove(script);
                }
            }

            if (ScriptSynchronizerUtils.hasClashingId(metadata.getId(), script)) {
                return;
            }

            // FIXME: Remove the usage of ByteBuddy when ExtensionPassiveScan does not rely on the
            // class name to remove scan rules
            var dynamicPassiveScanRuleType =
                    new ByteBuddy()
                            .subclass(PassiveScriptScanRule.class)
                            .make()
                            .load(getClass().getClassLoader(), ClassLoadingStrategy.Default.WRAPPER)
                            .getLoaded();
            scanRule =
                    dynamicPassiveScanRuleType
                            .getConstructor(ScriptWrapper.class, metadata.getClass())
                            .newInstance(script, metadata);

            if (!getExtPscan().addPluginPassiveScanner(scanRule)) {
                LOGGER.error("Failed to install script scan rule: {}", script.getName());
                return;
            }
            scriptToScanRuleMap.put(script, scanRule);
        } catch (Exception e) {
            getExtScript().handleScriptException(script, e);
        }
    }

    public void scriptRemoved(ScriptWrapper script) {
        try {
            PassiveScriptScanRule scanRule = scriptToScanRuleMap.get(script);
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

    private boolean unloadScanRule(PassiveScriptScanRule scanRule) {
        if (!getExtPscan().removePluginPassiveScanner(scanRule)) {
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

    private ExtensionPassiveScan getExtPscan() {
        if (extPscan == null) {
            extPscan =
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionPassiveScan.class);
        }
        return extPscan;
    }
}
