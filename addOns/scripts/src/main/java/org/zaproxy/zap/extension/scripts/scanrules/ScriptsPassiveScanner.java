/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
import net.htmlparser.jericho.Source;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.ExtensionPassiveScan;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.script.ScriptsCache;
import org.zaproxy.zap.extension.script.ScriptsCache.Configuration;

public class ScriptsPassiveScanner extends PassiveScriptHelper {

    private static final Logger LOGGER = LogManager.getLogger(ScriptsPassiveScanner.class);

    private final ScriptsCache<PassiveScript> scripts;

    private int currentHistoryType;

    public ScriptsPassiveScanner() {
        ExtensionScript extension =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionScript.class);
        scripts =
                extension != null
                        ? extension.createScriptsCache(
                                Configuration.<PassiveScript>builder()
                                        .setScriptType(ExtensionPassiveScan.SCRIPT_TYPE_PASSIVE)
                                        .setTargetInterface(PassiveScript.class)
                                        .setInterfaceProvider(
                                                (scriptWrapper, targetInterface) -> {
                                                    if (ScriptSynchronizerUtils.providesMetadata(
                                                            scriptWrapper)) {
                                                        return null;
                                                    }
                                                    var s =
                                                            extension.getInterface(
                                                                    scriptWrapper,
                                                                    PassiveScript.class);
                                                    if (s != null) {
                                                        return s;
                                                    }
                                                    extension.handleFailedScriptInterface(
                                                            scriptWrapper,
                                                            Constant.messages.getString(
                                                                    "scripts.scanRules.pscan.interfaceError",
                                                                    scriptWrapper.getName()));
                                                    return null;
                                                })
                                        .build())
                        : null;
    }

    @Override
    public String getName() {
        return Constant.messages.getString("scripts.scanRules.pscan.name");
    }

    @Override
    public int getPluginId() {
        return 50001;
    }

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        if (scripts == null) {
            return;
        }

        scripts.refreshAndExecute(
                (sw, script) -> {
                    if (appliesToCurrentHistoryType(sw, script)) {
                        script.scan(this, msg, source);
                    }
                });
    }

    @Override
    public ScriptsPassiveScanner copy() {
        ScriptsPassiveScanner copy = new ScriptsPassiveScanner();
        copy.currentHistoryType = currentHistoryType;
        return copy;
    }

    private boolean appliesToCurrentHistoryType(ScriptWrapper wrapper, PassiveScript ps) {
        try {
            return ps.appliesToHistoryType(currentHistoryType);
        } catch (UndeclaredThrowableException e) {
            // Python script implementation throws an exception if this optional/default method is
            // not
            // actually implemented by the script (other script implementations, Zest/ECMAScript,
            // just
            // use the default method).
            if (e.getCause() instanceof NoSuchMethodException
                    && "appliesToHistoryType".equals(e.getCause().getMessage())) {
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug(
                            "Script [Name={}, Engine={}]  does not implement the optional method appliesToHistoryType: ",
                            wrapper.getName(),
                            wrapper.getEngineName(),
                            e);
                }
                return super.appliesToHistoryType(currentHistoryType);
            }
            throw e;
        }
    }

    @Override
    public boolean appliesToHistoryType(int historyType) {
        this.currentHistoryType = historyType;
        return true;
    }
}
