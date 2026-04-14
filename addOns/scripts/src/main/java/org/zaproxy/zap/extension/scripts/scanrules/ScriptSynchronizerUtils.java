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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.PluginFactory;
import org.zaproxy.addon.commonlib.scanrules.ScanRuleMetadata;
import org.zaproxy.addon.commonlib.scanrules.ScanRuleMetadataProvider;
import org.zaproxy.addon.pscan.ExtensionPassiveScan2;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptWrapper;

class ScriptSynchronizerUtils {

    private static final Logger LOGGER = LogManager.getLogger(ScriptSynchronizerUtils.class);

    /**
     * Bundles metadata with a strong reference to the provider proxy. The caller MUST store {@code
     * providerRef} for as long as the scan rule is registered — if the proxy is GC'd, the GraalJS
     * {@code ScriptEngineCleaner} closes the engine and permanently poisons {@code
     * ScanRuleMetadata} class init for the JVM process.
     *
     * @see <a href="https://github.com/zaproxy/zaproxy/issues/9297">Issue 9297</a>
     */
    static class MetadataResult {
        final ScanRuleMetadata metadata;
        final Object providerRef;

        MetadataResult(ScanRuleMetadata metadata, Object providerRef) {
            this.metadata = metadata;
            this.providerRef = providerRef;
        }
    }

    /**
     * Returns metadata and the provider proxy in a single result. These MUST be obtained from a
     * single {@code getInterface()} call — splitting into two calls creates a window where the
     * first proxy can be GC'd before the caller stores it.
     */
    static MetadataResult getMetadataForScript(ScriptWrapper script) throws Exception {
        var metadataProvider = getExtScript().getInterface(script, ScanRuleMetadataProvider.class);
        if (metadataProvider != null) {
            var metadata =
                    ScriptScanRuleUtils.callOptionalScriptMethod(metadataProvider::getMetadata);
            if (metadata != null) {
                return new MetadataResult(metadata, metadataProvider);
            }
        }
        return null;
    }

    // Unlike getMetadataForScript(), this intentionally does NOT retain the provider reference.
    // It's only a probe — engine closure here does not affect scan rule registration.
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
            var pluginPassiveScanner = getExtPscan().getPassiveScannersManager().getScanRule(id);
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

    private static ExtensionPassiveScan2 getExtPscan() {
        return Control.getSingleton()
                .getExtensionLoader()
                .getExtension(ExtensionPassiveScan2.class);
    }
}
