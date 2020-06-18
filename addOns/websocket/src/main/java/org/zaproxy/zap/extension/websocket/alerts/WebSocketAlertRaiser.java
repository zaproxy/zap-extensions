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
package org.zaproxy.zap.extension.websocket.alerts;

import org.parosproxy.paros.core.scanner.Alert;
import org.zaproxy.zap.extension.websocket.WebSocketMessageDTO;
import org.zaproxy.zap.extension.websocket.alerts.WebSocketAlertWrapper.WebSocketAlertBuilder;
import org.zaproxy.zap.extension.websocket.pscan.WebSocketPassiveScanner;

/**
 * Used for building {@link WebSocketAlertWrapper} and raise them in an appropriate {@link
 * WebSocketAlertThread}
 */
public class WebSocketAlertRaiser extends WebSocketAlertBuilder {

    private WebSocketAlertThread alertThread;

    /**
     * Initialize the alert raiser for a plugin which associating with a specific {@link
     * WebSocketAlertThread}.
     *
     * @param alertThread the associating {@link WebSocketAlertThread}
     * @param pluginId ID of the plugin. See {@link WebSocketPassiveScanner#getId()}}
     */
    public WebSocketAlertRaiser(
            WebSocketAlertThread alertThread, int pluginId, WebSocketMessageDTO webSocketMessage) {
        super.setPluginId(pluginId);
        super.setSource(alertThread.getAlertSource());
        super.setMessage(webSocketMessage);
        this.alertThread = alertThread;
    }

    /**
     * Build and Raise the Alert
     *
     * @return the {@link WebSocketAlertWrapper} that is raised.
     * @throws IllegalStateException If Plugin ID, Alert Source or Name have not been set.
     * @see WebSocketAlertRaiser#setPluginId(int)
     * @see WebSocketAlertRaiser#setSource(Alert.Source)
     * @see WebSocketAlertRaiser#setName(String)
     */
    @Override
    public WebSocketAlertWrapper raise() {
        WebSocketAlertWrapper webSocketAlert = super.build();
        alertThread.raiseAlert(webSocketAlert);
        return webSocketAlert;
    }

    public static class WebSocketAlertScriptRaiser {
        public static WebSocketAlertRaiser getWebSocketAlertRaiser(
                WebSocketAlertRaiser webSocketAlertRaiser, int pluginId) {
            webSocketAlertRaiser.setPluginId(pluginId);
            return webSocketAlertRaiser;
        }
    }
}
