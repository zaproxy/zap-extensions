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
package org.zaproxy.zap.extension.websocket;

import java.util.List;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.websocket.WebSocketProxy.Initiator;
import org.zaproxy.zap.extension.websocket.WebSocketProxy.State;

/** @author Juha Kivekas */
public class WebSocketSenderScriptListener implements WebSocketSenderListener {

    private ExtensionScript extensionScript;

    WebSocketSenderScriptListener() {
        extensionScript =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionScript.class);
    }

    @Override
    public int getListenerOrder() {
        return 0;
    }

    @Override
    public void onMessageFrame(int channelId, WebSocketMessage message, Initiator initiator) {
        List<ScriptWrapper> scripts =
                extensionScript.getScripts(ExtensionWebSocket.SCRIPT_TYPE_WEBSOCKET_SENDER);
        WebSocketSenderScriptHelper helper = new WebSocketSenderScriptHelper(channelId, initiator);
        for (ScriptWrapper script : scripts) {
            try {
                if (script.isEnabled()) {
                    WebSocketSenderScript s =
                            extensionScript.getInterface(script, WebSocketSenderScript.class);
                    if (s != null) {
                        s.onMessageFrame(message, helper);
                    } else {
                        extensionScript.handleFailedScriptInterface(
                                script,
                                Constant.messages.getString(
                                        "websocket.script.error.websocketsender",
                                        script.getName()));
                    }
                }
            } catch (Exception e) {
                extensionScript.handleScriptException(script, e);
            }
        }
    }

    @Override
    public void onStateChange(State state, WebSocketProxy proxy) {}
}
