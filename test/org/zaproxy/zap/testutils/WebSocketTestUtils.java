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


package org.zaproxy.zap.testutils;

import org.zaproxy.zap.testutils.websocket.server.NanoWebSocketConnection;
import org.zaproxy.zap.testutils.websocket.server.NanoWebSocketTestServer;

import java.io.IOException;

/**
 * Class with utility/helper methods for general tests for WebSockets
 */
public abstract class WebSocketTestUtils extends TestUtils{

    /**
     * A WebSocket Test Server. The server is {@code null} if not started.
     */
    private NanoWebSocketTestServer webSocketTestServer;
    
    /**
     * Starts a WebSocket Server on specific hostname and port.
     */
    public void startWebSocketServer(String hostname, int webSocketPort, int timeout) throws IOException {
        if(webSocketTestServer == null){
            webSocketTestServer = new NanoWebSocketTestServer(hostname,webSocketPort);
        }
        webSocketTestServer.start(timeout);
    }
    
    public void startWebSocketServer(String hostname, int webSocketPort) throws IOException {
        startWebSocketServer(hostname,webSocketPort,5000);
    }
    
    
    public void stopWebSocketServer(){
        if(webSocketTestServer != null){
            webSocketTestServer.stop();
        }
    }
    
    /**
     * @return If WebServer was started return it, in any other case returns null
     */
    public NanoWebSocketTestServer getWebSocketTestServer() {
        return webSocketTestServer;
    }
    
    public NanoWebSocketConnection getLastConnection(){
        return webSocketTestServer.getLastConnection();
    }
    
    public NanoWebSocketConnection getConnection(int channelID){
        return webSocketTestServer.getConnection(channelID);
    }
    
}
