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

import java.lang.reflect.UndeclaredThrowableException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.PluginFactory;
import org.zaproxy.addon.commonlib.scanrules.ScanRuleMetadata;
import org.zaproxy.addon.commonlib.scanrules.ScanRuleMetadataProvider;
import org.zaproxy.zap.extension.pscan.ExtensionPassiveScan;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptWrapper;

class ScriptSynchronizerUtils {

    private static final Logger LOGGER = LogManager.getLogger(ScriptSynchronizerUtils.class);

    static ScanRuleMetadata getMetadataForScript(ScriptWrapper script) throws Exception {
        var metadataProvider = getExtScript().getInterface(script, ScanRuleMetadataProvider.class);
        if (metadataProvider != null) {
            try {
                return metadataProvider.getMetadata();
            } catch (UndeclaredThrowableException ignored) {
                // Python and Kotlin scripts throw this exception when the method is not implemented
                return null;
            } catch (Exception e) {
                if ("groovy.lang.MissingMethodException"
                        .equals(e.getCause().getClass().getCanonicalName())) {
                    // Groovy scripts throw this exception when the method is not implemented
                    return null;
                }
                throw e;
            }
        }
        return null;
    }

    static boolean providesMetadata(ScriptWrapper script) {
        try {
            var metadataProvider =
                    getExtScript().getInterface(script, ScanRuleMetadataProvider.class);
            if (metadataProvider != null) {
                metadataProvider.getMetadata();
                return true;
            }
        } catch (Exception ignored) {
        }
        return false;
    }

    static boolean hasClashingId(int id, ScriptWrapper script) {
        boolean hasClashingId = false;
        String existingRuleName = null;
        var loadedPlugin = PluginFactory.getLoadedPlugin(id);
        if (loadedPlugin != null) {
            hasClashingId = true;
            existingRuleName = loadedPlugin.getName();
        } else {
            var pluginPassiveScanner = getExtPscan().getPluginPassiveScanner(id);
            if (pluginPassiveScanner != null) {
                hasClashingId = true;
                existingRuleName = pluginPassiveScanner.getName();
            }
        }
        if (hasClashingId) {
            String message =
                    Constant.messages.getString(
                            "scripts.scanRules.duplicateId",
                            String.valueOf(id),
                            existingRuleName,
                            script.getName());
            LOGGER.error(message);
            getExtScript().setError(script, message);
            getExtScript().setEnabled(script, false);
        }
        return hasClashingId;
    }

    private static ExtensionScript getExtScript() {
        return Control.getSingleton().getExtensionLoader().getExtension(ExtensionScript.class);
    }

    private static ExtensionPassiveScan getExtPscan() {
        return Control.getSingleton().getExtensionLoader().getExtension(ExtensionPassiveScan.class);
    }
}
