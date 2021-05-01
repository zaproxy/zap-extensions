/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2012 The ZAP Development Team
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
package org.zaproxy.zap.extension.websocket.manualsend;

import javax.swing.JComboBox;
import org.zaproxy.zap.extension.httppanel.HttpPanelRequest;
import org.zaproxy.zap.view.HttpPanelManager;

/** Craft custom WebSocket message and send them. Avoid HTTP method panel to appear here. */
public class WebSocketSendPanel extends HttpPanelRequest {

    private static final long serialVersionUID = 1L;

    public WebSocketSendPanel(boolean isEditable, String configurationKey) {
        super(isEditable, configurationKey);
    }

    @Override
    protected void initComboChangeMethod() {
        if (comboChangeMethod == null) {
            comboChangeMethod = new JComboBox<>();
        }
    }

    public void unload() {
        HttpPanelManager.getInstance().removeRequestPanel(this);
    }
}
