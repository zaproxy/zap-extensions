/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2019 The ZAP Development Team
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
import javax.script.ScriptException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.control.Control;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.websocket.WebSocketMessageDTO;
import org.zaproxy.zap.extension.websocket.pscan.WebSocketScanHelper;

public class WebSocketPassiveScriptDecorator implements WebSocketPassiveScript {

    private static final Logger LOGGER =
            LogManager.getLogger(WebSocketPassiveScriptDecorator.class);

    private ScriptWrapper scriptWrapper;
    private WebSocketPassiveScript webSocketPassiveScript;
    private ExtensionScript extensionScript = null;

    WebSocketPassiveScriptDecorator(
            WebSocketPassiveScript webSocketPassiveScript, ScriptWrapper scriptWrapper) {
        this.webSocketPassiveScript = webSocketPassiveScript;
        this.scriptWrapper = scriptWrapper;
    }

    @Override
    public void scan(WebSocketScanHelper helper, WebSocketMessageDTO msg) {
        try {
            webSocketPassiveScript.scan(helper, msg);
        } catch (ScriptException e) {
            getExtension().handleScriptException(scriptWrapper, e);
        }
    }

    @Override
    public int getId() {
        try {
            return webSocketPassiveScript.getId();
        } catch (UndeclaredThrowableException e) {
            // Python script implementation throws an exception if this optional/default method is
            // not actually implemented by the script (other script implementations,
            // Zest/ECMAScript, just use the default method).
            if (e.getCause() instanceof NoSuchMethodException
                    && "getId".equals(e.getCause().getMessage())) {
                LOGGER.debug(
                        "Script [Name={}, Engine={}]  does not implement the optional method getId: ",
                        scriptWrapper.getName(),
                        scriptWrapper.getEngineName(),
                        e);
                return ScriptsWebSocketPassiveScanner.PLUGIN_ID;
            }
            getExtension().handleScriptException(scriptWrapper, e);
        }
        return ScriptsWebSocketPassiveScanner.PLUGIN_ID;
    }

    @Override
    public String getName() {
        try {
            return (webSocketPassiveScript
                            .getName()
                            .equals(ScriptsWebSocketPassiveScanner.PLUGIN_NAME))
                    ? scriptWrapper.getName()
                    : webSocketPassiveScript.getName();
        } catch (UndeclaredThrowableException e) {
            // Python script implementation throws an exception if this optional/default method is
            // not actually implemented by the script (other script implementations,
            // Zest/ECMAScript, jus tuse the default method).
            if (e.getCause() instanceof NoSuchMethodException
                    && "getName".equals(e.getCause().getMessage())) {
                LOGGER.debug(
                        "Script [Name={}, Engine={}]  does not implement the optional method getName: ",
                        scriptWrapper.getName(),
                        scriptWrapper.getEngineName(),
                        e);
                return scriptWrapper.getName();
            }
            getExtension().handleScriptException(scriptWrapper, e);
        }
        return scriptWrapper.getName();
    }

    private ExtensionScript getExtension() {
        if (extensionScript == null) {
            extensionScript =
                    Control.getSingleton().getExtensionLoader().getExtension(ExtensionScript.class);
        }
        return extensionScript;
    }
}
