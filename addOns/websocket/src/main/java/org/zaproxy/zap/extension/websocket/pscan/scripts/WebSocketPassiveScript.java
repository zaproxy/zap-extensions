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

import java.util.Collections;
import java.util.List;
import javax.script.ScriptException;
import org.parosproxy.paros.core.scanner.Alert;
import org.zaproxy.zap.extension.alert.ExampleAlertProvider;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.websocket.WebSocketMessageDTO;
import org.zaproxy.zap.extension.websocket.pscan.WebSocketPassiveScanner;
import org.zaproxy.zap.extension.websocket.pscan.WebSocketScanHelper;
import org.zaproxy.zap.extension.websocket.pscan.WebSocketScanHelperImpl;

/**
 * This interface is going to implemented by Zap Scripts. Interface uses the {@link
 * WebSocketPassiveScanner#scanMessage(org.zaproxy.zap.extension.websocket.pscan.WebSocketScanHelper,
 * WebSocketMessageDTO)} with {@link
 * org.zaproxy.zap.extension.script.ExtensionScript#getInterface(ScriptWrapper, Class)} in order to
 * run scripts with different scripting engines.
 */
public interface WebSocketPassiveScript extends ExampleAlertProvider {
    /**
     * Used for passive scanning the WebSocket Messages.
     *
     * @param helper WebSocketPassiveHelper providing methods to script. Method such as:
     *     <p>* {@link WebSocketScanHelper#newAlert()} which return a {@link
     *     org.zaproxy.zap.extension.websocket.alerts.WebSocketAlertRaiser} in order to build and
     *     raise alerts.
     * @param msg Message is going to be scanned
     * @throws ScriptException
     */
    void scan(WebSocketScanHelper helper, WebSocketMessageDTO msg) throws ScriptException;

    default int getId() {
        return ScriptsWebSocketPassiveScanner.PLUGIN_ID;
    }

    default String getName() {
        return ScriptsWebSocketPassiveScanner.PLUGIN_NAME;
    }

    @Override
    default List<Alert> getExampleAlerts() {
        return Collections.emptyList();
    }

    /** Only use for generating example alerts, not for raising them. */
    static WebSocketScanHelper getExampleHelper() {
        return new WebSocketScanHelperImpl();
    }
}
