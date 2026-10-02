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
import java.util.concurrent.Callable;
import org.zaproxy.addon.commonlib.scanrules.ScanRuleMetadata;
import org.zaproxy.addon.commonlib.scanrules.ScanRuleMetadataProvider;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptWrapper;

/**
 * Detects whether a WebSocket Passive Rule script declares {@link ScanRuleMetadata}, shared by
 * {@link WebSocketScriptSynchronizer} and {@link ScriptsWebSocketPassiveScanner} so both agree on
 * which scripts are metadata-backed (and therefore run as their own {@link
 * WebSocketPassiveScriptScanRule} rather than through the legacy bundling scanner).
 */
final class WebSocketScriptMetadataUtils {

    private WebSocketScriptMetadataUtils() {}

    /**
     * Returns {@code true} if {@code script} declares {@link ScanRuleMetadata}, invoking the
     * optional method to tell a genuine implementation from a script engine's proxy that merely
     * declares the interface (see {@link #getMetadata(ExtensionScript, ScriptWrapper)}).
     *
     * <p>Any exception raised while invoking the method (other than the "method not implemented"
     * cases already handled there) is treated as "no metadata", consistent with skipping the script
     * here — the exception will surface again, and be handled, when the script actually runs.
     */
    static boolean providesMetadata(ExtensionScript extScript, ScriptWrapper script) {
        try {
            return getMetadata(extScript, script) != null;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Returns the {@link ScanRuleMetadata} declared by {@code script}, or {@code null} if it
     * doesn't declare the {@link ScanRuleMetadataProvider} interface, or declares it but doesn't
     * actually implement the optional method (some script engines return a proxy for any declared
     * interface, regardless of what the script itself defines).
     */
    static ScanRuleMetadata getMetadata(ExtensionScript extScript, ScriptWrapper script)
            throws Exception {
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
}
