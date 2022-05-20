/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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

import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptType;
import org.zaproxy.zap.extension.script.ScriptsCache;
import org.zaproxy.zap.extension.script.ScriptsCache.Configuration;
import org.zaproxy.zap.extension.script.ScriptsCache.InterfaceProvider;
import org.zaproxy.zap.extension.websocket.ExtensionWebSocket;
import org.zaproxy.zap.extension.websocket.WebSocketMessageDTO;
import org.zaproxy.zap.extension.websocket.alerts.WebSocketAlertRaiser;
import org.zaproxy.zap.extension.websocket.pscan.WebSocketPassiveScanner;
import org.zaproxy.zap.extension.websocket.pscan.WebSocketScanHelper;

/**
 * Implements Scripting plugin for Passive Scan. The {@link ScriptType} should have been registered
 * at {@link ExtensionScript}. By default the plugin is disabled.
 */
public class ScriptsWebSocketPassiveScanner implements WebSocketPassiveScanner {

    public static final String PLUGIN_NAME = "WS.ScriptPassiveScan";
    public static final int PLUGIN_ID = 110000;

    private final ScriptsCache<WebSocketPassiveScript> scripts;

    public ScriptsWebSocketPassiveScanner(ExtensionScript extensionScript) {
        InterfaceProvider<WebSocketPassiveScript> interfaceProvider =
                (scriptWrapper, targetInterface) -> {
                    WebSocketPassiveScript s =
                            extensionScript.getInterface(scriptWrapper, targetInterface);
                    if (s != null) {
                        return new WebSocketPassiveScriptDecorator(s, scriptWrapper);
                    }
                    extensionScript.handleFailedScriptInterface(
                            scriptWrapper,
                            Constant.messages.getString(
                                    "websocket.pscan.scripts.interface.passive.error",
                                    scriptWrapper.getName()));
                    return null;
                };
        scripts =
                extensionScript.createScriptsCache(
                        Configuration.<WebSocketPassiveScript>builder()
                                .setScriptType(ExtensionWebSocket.SCRIPT_TYPE_WEBSOCKET_PASSIVE)
                                .setTargetInterface(WebSocketPassiveScript.class)
                                .setInterfaceProvider(interfaceProvider)
                                .build());
    }

    @Override
    public void scanMessage(WebSocketScanHelper helper, WebSocketMessageDTO webSocketMessage) {
        scripts.refreshAndExecute(
                (sw, script) ->
                        script.scan(
                                () ->
                                        WebSocketAlertRaiser.WebSocketAlertScriptRaiser
                                                .getWebSocketAlertRaiser(
                                                        helper.newAlert(), script.getId()),
                                webSocketMessage));
    }

    @Override
    public String getName() {
        return PLUGIN_NAME;
    }

    @Override
    public int getId() {
        return PLUGIN_ID;
    }
}
