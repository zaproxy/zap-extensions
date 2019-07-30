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
package org.zaproxy.zap.extension.websocket;

import java.io.IOException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.websocket.client.HandshakeConfig;
import org.zaproxy.zap.extension.websocket.client.HttpHandshakeBuilder;
import org.zaproxy.zap.extension.websocket.client.ServerConnectionEstablisher;
import org.zaproxy.zap.testutils.WebSocketTestUtils;

public abstract class WebSocketAddonTestUtils extends WebSocketTestUtils {

    public WebSocketProxy setupWebSocketProxy() {
        ServerConnectionEstablisher establisher = new ServerConnectionEstablisher();
        try {
            HttpMessage handshakeRequest =
                    new HttpMessage(
                            HttpHandshakeBuilder.getHttpHandshakeRequestHeader(
                                    super.getServerUrl()));
            return establisher.send(new HandshakeConfig(handshakeRequest, false, false));
        } catch (Exception e) {
            return null;
        }
    }

    public WebSocketMessageDTO sendOutgoingMessage(WebSocketProxy webSocketProxy, String message) {
        WebSocketMessageDTO webSocketMessage = new WebSocketMessageDTO(webSocketProxy.getDTO());
        webSocketMessage.payload = message;
        webSocketMessage.opcode = WebSocketMessage.OPCODE_TEXT;

        try {
            return webSocketProxy.send(webSocketMessage, WebSocketProxy.Initiator.MANUAL_REQUEST)
                    ? webSocketMessage
                    : null;
        } catch (IOException e) {
            return null;
        }
    }
}
