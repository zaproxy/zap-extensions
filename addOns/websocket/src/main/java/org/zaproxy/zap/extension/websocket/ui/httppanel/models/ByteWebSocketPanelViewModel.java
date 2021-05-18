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
package org.zaproxy.zap.extension.websocket.ui.httppanel.models;

import java.nio.charset.Charset;
import org.zaproxy.zap.extension.websocket.WebSocketMessage;

public class ByteWebSocketPanelViewModel extends AbstractWebSocketBytePanelViewModel {

    @Override
    public byte[] getData() {
        if (webSocketMessage == null || webSocketMessage.getPayload() == null) {
            return new byte[0];
        }

        if (webSocketMessage.getPayload() instanceof String) {
            return ((String) webSocketMessage.getPayload()).getBytes();
        } else if (webSocketMessage.getPayload() instanceof byte[]) {
            return (byte[]) webSocketMessage.getPayload();
        }

        return new byte[0];
    }

    @Override
    public void setData(byte[] data) {
        if (webSocketMessage.getOpcode() != null) {
            if (webSocketMessage.getOpcode() == WebSocketMessage.OPCODE_BINARY) {
                webSocketMessage.setPayload(data);
            } else {
                webSocketMessage.setPayload(new String(data, Charset.forName("UTF-8")));
            }
        } else {
            if (webSocketMessage.getPayload() instanceof String) {
                webSocketMessage.setPayload(new String(data, Charset.forName("UTF-8")));
            } else if (webSocketMessage.getPayload() instanceof byte[]) {
                webSocketMessage.setPayload(data);
            }
        }
    }
}
