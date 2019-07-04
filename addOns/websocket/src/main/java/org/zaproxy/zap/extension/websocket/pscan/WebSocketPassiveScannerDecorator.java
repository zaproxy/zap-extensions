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
package org.zaproxy.zap.extension.websocket.pscan;

import org.zaproxy.zap.extension.websocket.WebSocketMessageDTO;
import org.zaproxy.zap.utils.EnableableInterface;

class WebSocketPassiveScannerDecorator implements WebSocketPassiveScanner, EnableableInterface {

    private final WebSocketPassiveScanner webSocketPassiveScanner;

    private boolean isEnabled = false;

    public WebSocketPassiveScannerDecorator(WebSocketPassiveScanner webSocketPassiveScanner) {
        this.webSocketPassiveScanner = webSocketPassiveScanner;
    }

    @Override
    public String getName() {
        return webSocketPassiveScanner.getName();
    }

    @Override
    public void scanMessage(WebSocketScanHelper helper, WebSocketMessageDTO webSocketMessage) {
        webSocketPassiveScanner.scanMessage(helper, webSocketMessage);
    }

    @Override
    public int getId() {
        return webSocketPassiveScanner.getId();
    }

    @Override
    public int hashCode() {
        return webSocketPassiveScanner.getId();
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (this == obj) {
            return true;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }

        WebSocketPassiveScanner other = (WebSocketPassiveScanner) obj;
        if (this.getId() == other.getId() || this.getName() == other.getName()) {
            return true;
        }
        return false;
    }

    @Override
    public boolean isEnabled() {
        return isEnabled;
    }

    @Override
    public void setEnabled(boolean enabled) {
        isEnabled = enabled;
    }
}
