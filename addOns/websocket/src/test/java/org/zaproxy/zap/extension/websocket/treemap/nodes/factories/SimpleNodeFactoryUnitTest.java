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
package org.zaproxy.zap.extension.websocket.treemap.nodes.factories;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.zap.extension.websocket.ExtensionWebSocket;
import org.zaproxy.zap.extension.websocket.WebSocketChannelDTO;
import org.zaproxy.zap.extension.websocket.WebSocketProxy;
import org.zaproxy.zap.extension.websocket.client.HttpHandshakeBuilder;
import org.zaproxy.zap.extension.websocket.treemap.nodes.namers.WebSocketSimpleNodeNamer;
import org.zaproxy.zap.testutils.WebSocketTestUtils;

public class SimpleNodeFactoryUnitTest extends WebSocketTestUtils {

    private NodeFactory nodeFactory;

    @Before
    public void setUp() throws Exception {
        setUpMessages();
        super.setUpLog();
        super.startWebSocketServer("localhost");
        nodeFactory = new SimpleNodeFactory(new WebSocketSimpleNodeNamer());
    }

    @Override
    protected void setUpMessages() {
        mockMessages(new ExtensionWebSocket());
    }

    private HistoryReference getMockHistoryReference(URI serverUrl)
            throws HttpMalformedHeaderException, DatabaseException {

        HttpRequestHeader handshakeRequest =
                HttpHandshakeBuilder.getHttpHandshakeRequestHeader(serverUrl);
        HttpMessage handshakeMessage = new HttpMessage(handshakeRequest);

        HistoryReference historyReference = mock(HistoryReference.class);
        when(historyReference.getURI()).thenReturn(serverUrl);
        when(historyReference.getHttpMessage()).thenReturn(handshakeMessage);
        return historyReference;
    }

    private WebSocketProxy getMockWebSocketProxy(
            HistoryReference handshakeRef, WebSocketChannelDTO channel) {
        WebSocketProxy proxy = mock(WebSocketProxy.class);
        when(proxy.getDTO()).thenReturn(channel);
        when(proxy.getHandshakeReference()).thenReturn(handshakeRef);
        when(proxy.getChannelId()).thenReturn(channel.id);
        return proxy;
    }

    private WebSocketChannelDTO getWebSocketChannelDTO(int id, String hostName) {
        WebSocketChannelDTO channel = new WebSocketChannelDTO(hostName);
        channel.id = id;
        channel.port = 443;
        channel.url = hostName;
        return channel;
    }

    @Test
    public void shouldGetChildIfNotContained()
            throws DatabaseException, HttpMalformedHeaderException, URIException {

        // Given
        for (int i = 0; i < 10; i++) {
            HistoryReference historyReference =
                    getMockHistoryReference(new URI("hostname_" + i % 2, true));
            WebSocketChannelDTO channel = getWebSocketChannelDTO(i, "hostname_" + i % 2);

            // When
            nodeFactory.getHandshakeTreeNode(getMockWebSocketProxy(historyReference, channel));
        }
        System.out.print(nodeFactory.getRoot());
        Collection<List<HistoryReference>> handshakeRefs =
                nodeFactory
                        .getRoot()
                        .getHandshakesReferencesPerHost(nodeFactory.getRoot(), new HashMap<>())
                        .values();
        System.out.println(handshakeRefs);
        Assert.assertEquals(handshakeRefs.size(), 2);
    }
}
