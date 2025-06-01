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
package org.zaproxy.zap.extension.websocket.pscan;

import org.zaproxy.zap.extension.websocket.WebSocketMessageDTO;
import org.zaproxy.zap.extension.websocket.alerts.WebSocketAlertRaiser;
import org.zaproxy.zap.extension.websocket.alerts.WebSocketAlertThread;

/**
 * This class passed into {@link WebSocketPassiveScanner#scanMessage(WebSocketScanHelper,
 * WebSocketMessageDTO)} so as to provide extra functionality at WebSocket Passive scan plugin and
 * script
 */
public class WebSocketScanHelperImpl implements WebSocketScanHelper {

    private WebSocketAlertThread webSocketAlertThread;
    private int pluginId;
    private WebSocketMessageDTO webSocketMessage;

    /** Only to be used for the example alerts, will not be able to raise any this way. */
    public WebSocketScanHelperImpl() {
        this.webSocketAlertThread = new WebSocketPassiveScanThread(null);
    }

    /**
     * @param webSocketAlertThread the parent thread of helper which is responsible for the alert.
     */
    public WebSocketScanHelperImpl(WebSocketAlertThread webSocketAlertThread) {
        this.webSocketAlertThread = webSocketAlertThread;
    }

    /**
     * Setting and returns the current instance.
     *
     * @param pluginId pluginId ID of the plugin. See {@link WebSocketPassiveScanner#getId()}}
     * @param webSocketMessage WebSocket Message is going to be scanned
     * @return
     */
    public WebSocketScanHelper getWebSocketScanHelper(
            int pluginId, WebSocketMessageDTO webSocketMessage) {
        this.pluginId = pluginId;
        this.webSocketMessage = webSocketMessage;
        return this;
    }

    @Override
    public WebSocketAlertRaiser newAlert() {
        return new WebSocketAlertRaiser(webSocketAlertThread, pluginId, webSocketMessage);
    }
}
