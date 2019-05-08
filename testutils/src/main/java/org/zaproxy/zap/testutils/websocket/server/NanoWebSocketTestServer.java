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
package org.zaproxy.zap.testutils.websocket.server;

import fi.iki.elonen.NanoWSD;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/** Creates a simple WebSocket Test Server. Stores every connection was established */
public class NanoWebSocketTestServer extends NanoWSD {

    private List<NanoWebSocketConnection> connectionsList;
    private static final String DEFAULT_PING_MESSAGE = "PING";
    private static final String CLOSE_REASON_CANT_SENT = "Connection Lost";
    private static final String CLOSE_REASON_REQUIREMENT = "Requirement";

    private boolean isSecure = false;

    public NanoWebSocketTestServer(String hostname, int port) {
        super(hostname, port);
        connectionsList = new ArrayList<>();
    }

    public NanoWebSocketTestServer(int port) {
        this(null, port);
    }

    /** Returns the last connection established on server */
    public NanoWebSocketConnection getLastConnection() {
        return connectionsList.size() > 0 ? connectionsList.get(connectionsList.size() - 1) : null;
    }

    @Override
    protected WebSocket openWebSocket(IHTTPSession ihttpSession) {
        NanoWebSocketConnection webSocketConnection = new NanoWebSocketConnection(ihttpSession);
        webSocketConnection.setPingMessage(DEFAULT_PING_MESSAGE.getBytes(StandardCharsets.UTF_8));

        connectionsList.add(webSocketConnection);

        return webSocketConnection;
    }

    /**
     * Send the same message to connected websockets. If connection was closed, removes it from the
     * list
     */
    public void sendToAll(String str) {
        for (NanoWebSocketConnection connection : connectionsList) {
            try {
                connection.send(str);
            } catch (IOException e) {
                try {
                    connection.close(
                            WebSocketFrame.CloseCode.InvalidFramePayloadData,
                            CLOSE_REASON_CANT_SENT,
                            false);
                } catch (IOException e1) {
                    e1.printStackTrace();
                }
                connectionsList.remove(connection);
            }
        }
    }

    /** Disconnect and remove from the list all websocket connections */
    public void disconnectAll() {
        for (int i = 0; i < connectionsList.size(); i++) {
            NanoWebSocketConnection ws = connectionsList.get(i);
            try {
                ws.close(
                        WebSocketFrame.CloseCode.InvalidFramePayloadData,
                        CLOSE_REASON_REQUIREMENT,
                        false);
            } catch (IOException e) {
                e.printStackTrace();
            }
            connectionsList.remove(ws);
        }
    }

    /** Get connection by channelId. */
    public NanoWebSocketConnection getConnection(int channelId) {
        return connectionsList.get(channelId);
    }

    public boolean isSecure() {
        return isSecure;
    }
}
