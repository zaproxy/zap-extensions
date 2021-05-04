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
package org.zaproxy.zap.extension.websocket.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.websocket.ExtensionWebSocket;
import org.zaproxy.zap.extension.websocket.WebSocketProxy;
import org.zaproxy.zap.extension.websocket.utility.WebSocketUtils;
import org.zaproxy.zap.testutils.WebSocketTestUtils;
import org.zaproxy.zap.testutils.websocket.server.NanoWebSocketConnection;
import org.zaproxy.zap.testutils.websocket.server.NanoWebSocketTestServer;

class ServerConnectionEstablisherUnitTest extends WebSocketTestUtils {
    private static final String HOST_NAME = "localhost";

    @BeforeEach
    void openWebSocketServer() throws Exception {
        super.startWebSocketServer(HOST_NAME);
        super.setUpZap();
    }

    @AfterEach
    @Override
    public void stopWebSocketServer() {
        super.stopWebSocketServer();
    }

    @Override
    protected void setUpMessages() {
        mockMessages(new ExtensionWebSocket());
    }

    @Test
    void shouldReceiveUpgradeStatusCode() throws Exception {
        ServerConnectionEstablisher establisher = new ServerConnectionEstablisher();
        NanoWebSocketTestServer webSocketServer = super.getWebSocketTestServer();
        HttpMessage handshakeRequest =
                new HttpMessage(
                        HttpHandshakeBuilder.getHttpHandshakeRequestHeader(super.getServerUrl()));
        establisher.send(new HandshakeConfig(handshakeRequest, false, false));
        assertEquals(101, handshakeRequest.getResponseHeader().getStatusCode());
        assertEquals(
                webSocketServer
                        .getLastConnection()
                        .getHandshakeResponse()
                        .getHeader(HttpHandshakeBuilder.SEC_WEB_SOCKET_ACCEPT),
                WebSocketUtils.encodeWebSocketKey(
                        handshakeRequest
                                .getRequestHeader()
                                .getHeader(HttpHandshakeBuilder.SEC_WEB_SOCKET_KEY)));
    }

    @Test
    void shouldReturnWSProxy() throws Exception {
        ServerConnectionEstablisher establisher = new ServerConnectionEstablisher();
        HttpMessage handshakeRequest =
                new HttpMessage(
                        HttpHandshakeBuilder.getHttpHandshakeRequestHeader(super.getServerUrl()));
        WebSocketProxy webSocketProxy =
                establisher.send(new HandshakeConfig(handshakeRequest, false, false));
        NanoWebSocketConnection webSocketConnection =
                super.getWebSocketTestServer().getLastConnection();
        assertEquals(101, handshakeRequest.getResponseHeader().getStatusCode());
        assertNotNull(webSocketProxy);
        assertTrue(webSocketProxy.isConnected());
        assertEquals(
                webSocketConnection
                        .getHandshakeResponse()
                        .getHeader(HttpHandshakeBuilder.SEC_WEB_SOCKET_ACCEPT),
                WebSocketUtils.encodeWebSocketKey(
                        handshakeRequest
                                .getRequestHeader()
                                .getHeader(HttpHandshakeBuilder.SEC_WEB_SOCKET_KEY)));
    }
}
