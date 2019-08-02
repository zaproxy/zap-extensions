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
package org.zaproxy.zap.extension.websocket.treemap.nodes.content;

import java.util.ArrayList;
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
import org.zaproxy.zap.extension.websocket.ExtensionWebSocket;
import org.zaproxy.zap.extension.websocket.WebSocketAddonTestUtils;
import org.zaproxy.zap.extension.websocket.WebSocketChannelDTO;
import org.zaproxy.zap.extension.websocket.WebSocketProxy;
import org.zaproxy.zap.extension.websocket.treemap.nodes.WebSocketNode;
import org.zaproxy.zap.extension.websocket.treemap.nodes.contents.HandshakeContent;
import org.zaproxy.zap.extension.websocket.treemap.nodes.contents.HandshakeFolderContent;
import org.zaproxy.zap.extension.websocket.treemap.nodes.contents.HostFolderContent;
import org.zaproxy.zap.extension.websocket.treemap.nodes.contents.RootContent;
import org.zaproxy.zap.extension.websocket.treemap.nodes.contents.WebSocketContent;
import org.zaproxy.zap.extension.websocket.treemap.nodes.namers.WebSocketSimpleNodeNamer;
import org.zaproxy.zap.extension.websocket.treemap.nodes.structural.TreeNode;

public class HandshakeContentUnitTest extends WebSocketAddonTestUtils {

    private WebSocketSimpleNodeNamer namer;
    private static URI defaultHostName;
    TreeNode<WebSocketContent> root;

    @Before
    public void setUp() throws Exception {
        this.setUpMessages();
        namer = new WebSocketSimpleNodeNamer();
        defaultHostName = new URI("hostname", true);
        root = new WebSocketNode(null, new RootContent(namer));
    }

    @Override
    protected void setUpMessages() {
        mockMessages(new ExtensionWebSocket());
    }

    @Test
    public void shouldBeTheSameAndEqual()
            throws DatabaseException, HttpMalformedHeaderException, URIException {

        // Given
        URI handshakeUri1 = new URI("https", null, defaultHostName.toString(), -1, "/first");
        URI handshakeUri2 = new URI("https", null, defaultHostName.toString(), -1, "/first");

        // When
        HandshakeContent content1 =
                new HandshakeContent(
                        namer,
                        getMockWebSocketProxy(
                                getMockHistoryReference(handshakeUri1),
                                getWebSocketChannelDTO(
                                        1, handshakeUri1.toString(), handshakeUri1.toString())));

        HandshakeContent content2 =
                new HandshakeContent(
                        namer,
                        getMockWebSocketProxy(
                                getMockHistoryReference(handshakeUri2),
                                getWebSocketChannelDTO(
                                        2, defaultHostName.toString(), handshakeUri2.toString())));

        // Then
        Assert.assertEquals(0, content1.compareTo(content2));
        Assert.assertEquals(0, content2.compareTo(content1));
        Assert.assertTrue(content1.equals(content2));
        Assert.assertTrue(content2.equals(content1));
    }

    @Test
    public void shouldNotBeTheSameAndNotEqual()
            throws DatabaseException, HttpMalformedHeaderException, URIException {
        // Given
        URI handshakeUri1 = new URI("https", null, defaultHostName.toString(), -1, "/first");
        URI handshakeUri2 = new URI("https", null, defaultHostName.toString(), -1, "/second");

        // When
        HandshakeContent content1 =
                new HandshakeContent(
                        namer,
                        getMockWebSocketProxy(
                                getMockHistoryReference(handshakeUri1),
                                getWebSocketChannelDTO(
                                        1, defaultHostName.toString(), handshakeUri1.toString())));
        HandshakeContent content2 =
                new HandshakeContent(
                        namer,
                        getMockWebSocketProxy(
                                getMockHistoryReference(handshakeUri2),
                                getWebSocketChannelDTO(
                                        2, defaultHostName.toString(), handshakeUri2.toString())));

        // Then
        Assert.assertTrue(content1.compareTo(content2) < 0);
        Assert.assertTrue(content2.compareTo(content1) > 0);
        Assert.assertFalse(content1.equals(content2));
        Assert.assertFalse(content2.equals(content1));
    }

    @Test
    public void shouldCloneBeTheSame()
            throws URIException, DatabaseException, HttpMalformedHeaderException {
        // Given
        URI handshakeUri1 = new URI("https", null, defaultHostName.toString(), -1, "/first");
        HandshakeContent content1 =
                new HandshakeContent(
                        namer,
                        getMockWebSocketProxy(
                                getMockHistoryReference(handshakeUri1),
                                getWebSocketChannelDTO(
                                        1, defaultHostName.toString(), handshakeUri1.toString())));
        // When
        HandshakeContent cloneContent = content1.clone();

        // Then
        Assert.assertEquals(0, cloneContent.compareTo(content1));
        Assert.assertEquals(0, content1.compareTo(cloneContent));
    }

    @Test
    public void shouldGetHostNodes()
            throws DatabaseException, HttpMalformedHeaderException, URIException {

        // Given
        URI handshakeUri1 = new URI("https", null, defaultHostName.toString(), -1, "/first");
        WebSocketProxy proxy =
                getMockWebSocketProxy(
                        getMockHistoryReference(handshakeUri1),
                        getWebSocketChannelDTO(
                                1, defaultHostName.toString(), handshakeUri1.toString()));

        HandshakeContent content1 = new HandshakeContent(namer, proxy);
        TreeNode<WebSocketContent> hostNode =
                new WebSocketNode(root, new HostFolderContent(namer, proxy));

        TreeNode<WebSocketContent> handshakeFolder =
                new WebSocketNode(hostNode, new HandshakeFolderContent(namer));
        TreeNode<WebSocketContent> handshakeNode = new WebSocketNode(handshakeFolder, content1);

        // When
        List<TreeNode<WebSocketContent>> actualHostsList =
                handshakeNode.getHostNodes(handshakeNode, new ArrayList<>());

        // Then
        Assert.assertEquals(1, actualHostsList.size());
        Assert.assertEquals(hostNode, actualHostsList.get(0));
    }

    @Test
    public void shouldGetChannelsAndHandshakeRefPerHost()
            throws URIException, DatabaseException, HttpMalformedHeaderException {
        String[] hosts = {"hostname_1", "hostname_2"};
        ArrayList<TreeNode<WebSocketContent>> hostNodes = new ArrayList<>();
        ArrayList<TreeNode<WebSocketContent>> handshakeFolderNode = new ArrayList<>();
        ArrayList<TreeNode<WebSocketContent>> handshakeNodes = new ArrayList<>();

        // Given
        for (int i = 0; i < 5; i++) {
            URI handshakeUri1 = new URI("https", null, hosts[i % 2], -1, "/sth");
            WebSocketProxy proxy =
                    getMockWebSocketProxy(
                            getMockHistoryReference(handshakeUri1),
                            getWebSocketChannelDTO(i, hosts[i % 2], handshakeUri1.toString()));

            if (i < 2) {
                hostNodes.add(new WebSocketNode(root, new HostFolderContent(namer, proxy)));
                handshakeFolderNode.add(
                        new WebSocketNode(hostNodes.get(i), new HandshakeFolderContent(namer)));

                handshakeNodes.add(
                        new WebSocketNode(
                                handshakeFolderNode.get(i % 2),
                                new HandshakeContent(namer, proxy)));

            } else {
                handshakeNodes
                        .get(i % 2)
                        .getContent()
                        .addToContent(new HandshakeContent(namer, proxy));
            }
        }

        // When
        List<WebSocketChannelDTO> channelsHost1 =
                root.getChannelsPerHost(root, new HashMap<>()).get(hostNodes.get(0));
        List<WebSocketChannelDTO> channelsHost2 =
                root.getChannelsPerHost(root, new HashMap<>()).get(hostNodes.get(1));

        List<HistoryReference> refHost1 =
                root.getHandshakesReferencesPerHost(root, new HashMap<>()).get(hostNodes.get(0));
        List<HistoryReference> refHost2 =
                root.getHandshakesReferencesPerHost(root, new HashMap<>()).get(hostNodes.get(1));

        // Then
        Assert.assertEquals(3, channelsHost1.size());
        Assert.assertEquals(2, channelsHost2.size());

        Assert.assertEquals(3, refHost1.size());
        Assert.assertEquals(2, refHost2.size());
    }
}
