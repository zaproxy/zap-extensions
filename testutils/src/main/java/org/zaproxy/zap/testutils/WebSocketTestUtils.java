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

import java.io.IOException;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.zaproxy.zap.testutils.websocket.server.NanoWebSocketConnection;
import org.apache.commons.httpclient.URI;
import org.mockito.Mockito;
import org.mockito.stubbing.Answer;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.testutils.websocket.server.NanoWebSocketTestServer;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import static org.mockito.Mockito.when;

/** Class with utility/helper methods for general tests for WebSockets */
public abstract class WebSocketTestUtils extends TestUtils {

    public static final int DEFAULT_TIMEOUT = 5000;

    /** A WebSocket Test Server. The server is {@code null} if not started. */
    private NanoWebSocketTestServer webSocketTestServer;

    /** Starts a WebSocket Server on specific hostname and port. */
    public void startWebSocketServer(String hostname, int webSocketPort, int timeout)
            throws IOException {
        if (webSocketTestServer == null) {
            webSocketTestServer = new NanoWebSocketTestServer(hostname, webSocketPort);
        }
        webSocketTestServer.start(timeout);
    }

    /** Starts a WebSocket Server on specific hostname and port. */
    public void startWebSocketServer(String hostname, int webSocketPort) throws IOException {
        startWebSocketServer(hostname, webSocketPort, DEFAULT_TIMEOUT);
    }

    /** Start the Server at random port with standard timeout 5000 */
    public void startWebSocketServer(String hostname) throws IOException {
        startWebSocketServer(hostname, 0, DEFAULT_TIMEOUT);
    }

    public void stopWebSocketServer() {
        if (webSocketTestServer != null) {
            webSocketTestServer.stop();
        }
    }

    /** @return If WebServer was started return it, in any other case returns null */
    public NanoWebSocketTestServer getWebSocketTestServer() {
        return webSocketTestServer;
    }

    public NanoWebSocketConnection getLastConnection() {
        return webSocketTestServer.getLastConnection();
    }

    public NanoWebSocketConnection getConnection(int channelID) {
        return webSocketTestServer.getConnection(channelID);
    }

    public int getListeningPort() {
        return webSocketTestServer.getListeningPort();
    }

    public String getHostName() {
        return webSocketTestServer.getHostname();
    }

    public URI getServerUrl() throws URIException {
        return new URI(
                webSocketTestServer.isSecure() ? "https" : "http",
                null,
                webSocketTestServer.getHostname(),
                webSocketTestServer.getListeningPort());
    }

    private List<HttpMessage> httpMessagesHistory;
    
    public HistoryReference getMockHistoryReference(final HttpMessage httpMessage) throws DatabaseException, HttpMalformedHeaderException {
        if(httpMessagesHistory == null){
            httpMessagesHistory = new ArrayList<>();
        }
        httpMessagesHistory.add(httpMessage);
        final int index = httpMessagesHistory.size() - 1;
        
        HistoryReference historyReference = Mockito.mock(HistoryReference.class);
        when(historyReference.getHistoryId()).thenAnswer((Answer<Integer>) invocationOnMock -> index);
        
        when(historyReference.getHttpMessage()).thenAnswer((Answer<HttpMessage>) invocationOnMock -> httpMessage);
        when(historyReference.getURI()).thenAnswer( (Answer<URI>) invocationOnMock -> httpMessage.getRequestHeader().getURI());
        
        return historyReference;
    }

}
