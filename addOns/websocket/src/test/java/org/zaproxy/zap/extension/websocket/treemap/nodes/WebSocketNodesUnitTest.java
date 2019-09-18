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
package org.zaproxy.zap.extension.websocket.treemap.nodes;

import static org.hamcrest.Matchers.is;

import java.util.*;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.zaproxy.zap.extension.websocket.*;
import org.zaproxy.zap.extension.websocket.treemap.nodes.contents.*;
import org.zaproxy.zap.extension.websocket.treemap.nodes.namers.WebSocketSimpleNodeNamer;
import org.zaproxy.zap.extension.websocket.treemap.nodes.structural.TreeNode;

public class WebSocketNodesUnitTest extends WebSocketAddonTestUtils {

    private WebSocketNode rootFolder;
    private WebSocketSimpleNodeNamer namer;
    private static URI defaultHostName;

    @Before
    public void setUp() throws Exception {
        setUpMessages();
        super.setUpLog();

        namer = new WebSocketSimpleNodeNamer();
        rootFolder = new WebSocketNode(null, new RootContent(namer));
        defaultHostName = new URI("hostname", true);
    }

    @Override
    protected void setUpMessages() {
        mockMessages(new ExtensionWebSocket());
    }

    @Test
    public void shouldAddParentsAndChildren()
            throws DatabaseException, HttpMalformedHeaderException {

        // Given
        WebSocketProxy proxy =
                getMockWebSocketProxy(
                        getMockHistoryReference(defaultHostName),
                        getWebSocketChannelDTO(1, defaultHostName.toString()));

        // When
        WebSocketNode hostNode = new WebSocketNode(rootFolder, new HostFolderContent(namer, proxy));

        WebSocketNode handshakeSimpleWebSocketNode =
                new WebSocketNode(hostNode, new HandshakeFolderContent(namer));
        WebSocketNode handshakeNode =
                new WebSocketNode(handshakeSimpleWebSocketNode, new HandshakeContent(namer, proxy));

        // Then
        Assert.assertEquals(rootFolder.getChildren().get(0), hostNode);
        Assert.assertEquals(hostNode.getParent(), rootFolder);
        Assert.assertEquals(handshakeSimpleWebSocketNode.getChildren().get(0), handshakeNode);
    }

    @Test
    public void shouldGetContent() throws DatabaseException, HttpMalformedHeaderException {
        // Given
        WebSocketProxy proxy =
                getMockWebSocketProxy(
                        getMockHistoryReference(defaultHostName),
                        getWebSocketChannelDTO(1, defaultHostName.toString()));
        WebSocketMessageDTO message = new WebSocketMessageDTO();
        message.opcode = WebSocketMessage.OPCODE_TEXT;
        message.id = proxy.getChannelId();
        message.payload = "TestMessage";

        // When
        HostFolderContent hostContent = new HostFolderContent(namer, proxy);
        WebSocketNode hostNode = new WebSocketNode(rootFolder, hostContent);

        WebSocketNode handshakeSimpleWebSocketNode =
                new WebSocketNode(hostNode, new HandshakeFolderContent(namer));
        WebSocketNode messagesSimpleWebSocketNode =
                new WebSocketNode(
                        hostNode, new MessageFolderContent(namer, WebSocketMessage.OPCODE_TEXT));

        WebSocketNode handshakeNode =
                new WebSocketNode(handshakeSimpleWebSocketNode, new HandshakeContent(namer, proxy));
        WebSocketNode messageNode =
                new WebSocketNode(messagesSimpleWebSocketNode, new MessageContent(namer, message));

        // Then
        Assert.assertEquals(
                handshakeNode.getHandshakeReferences().get(0), proxy.getHandshakeReference());
        Assert.assertEquals(messageNode.getMessage(), message);
    }

    @Test
    public void shouldGetMessages() throws DatabaseException, HttpMalformedHeaderException {
        // Given
        WebSocketChannelDTO channel = getWebSocketChannelDTO(1, defaultHostName.toString());
        WebSocketProxy proxy =
                getMockWebSocketProxy(getMockHistoryReference(defaultHostName), channel);

        ArrayList<WebSocketMessageDTO> expectedMessagesList = new ArrayList<>();

        expectedMessagesList.add(
                getWebSocketMessageDTO(
                        channel, WebSocketMessage.OPCODE_TEXT, false, "Message #1", 1));
        expectedMessagesList.add(
                getWebSocketMessageDTO(
                        channel, WebSocketMessage.OPCODE_TEXT, false, "Message #2", 2));
        expectedMessagesList.add(
                getWebSocketMessageDTO(
                        channel, WebSocketMessage.OPCODE_TEXT, false, "Message #3", 3));

        // When
        HostFolderContent hostContent = new HostFolderContent(namer, proxy);
        WebSocketNode hostNode = new WebSocketNode(rootFolder, hostContent);

        WebSocketNode messagesSimpleWebSocketNode =
                new WebSocketNode(
                        hostNode, new MessageFolderContent(namer, WebSocketMessage.OPCODE_TEXT));
        WebSocketNode handshakeSimpleWebSocketNode =
                new WebSocketNode(hostNode, new HandshakeFolderContent(namer));
        for (WebSocketMessageDTO message : expectedMessagesList) {
            new WebSocketNode(messagesSimpleWebSocketNode, new MessageContent(namer, message));
        }

        // Then
        for (WebSocketMessageDTO message : expectedMessagesList) {
            Assert.assertTrue(rootFolder.getMessages().contains(message));
            Assert.assertTrue(hostNode.getMessages().contains(message));
            Assert.assertTrue(messagesSimpleWebSocketNode.getMessages().contains(message));
            Assert.assertTrue(handshakeSimpleWebSocketNode.getMessages().isEmpty());
        }
    }

    @Test
    public void shouldGetHandshakesAndChannels()
            throws DatabaseException, HttpMalformedHeaderException, URIException {

        // Given
        ArrayList<WebSocketProxy> proxies = new ArrayList<>();
        ArrayList<HistoryReference> expectedHistoryReferences = new ArrayList<>();
        ArrayList<WebSocketChannelDTO> expectedChannels = new ArrayList<>();

        proxies.add(
                getMockWebSocketProxy(
                        getMockHistoryReference(new URI(defaultHostName.toString() + "/#1", true)),
                        getWebSocketChannelDTO(1, defaultHostName.toString())));
        proxies.add(
                getMockWebSocketProxy(
                        getMockHistoryReference(new URI(defaultHostName.toString() + "/#2", true)),
                        getWebSocketChannelDTO(2, defaultHostName.toString())));
        proxies.add(
                getMockWebSocketProxy(
                        getMockHistoryReference(new URI(defaultHostName.toString() + "/#3", true)),
                        getWebSocketChannelDTO(3, defaultHostName.toString())));

        // When
        HostFolderContent hostContent = new HostFolderContent(namer, proxies.get(0));
        WebSocketNode hostNode = new WebSocketNode(rootFolder, hostContent);

        WebSocketNode messagesFolder =
                new WebSocketNode(
                        hostNode, new MessageFolderContent(namer, WebSocketMessage.OPCODE_TEXT));
        WebSocketNode handshakeFolder =
                new WebSocketNode(hostNode, new HandshakeFolderContent(namer));

        TreeNode<WebSocketContent> handshakeNode = null;
        for (int i = 0; i < proxies.size(); i++) {
            if (i == 0) {
                handshakeNode =
                        new WebSocketNode(
                                handshakeFolder, new HandshakeContent(namer, proxies.get(i)));

            } else {
                handshakeNode
                        .getContent()
                        .addToContent(new HandshakeContent(namer, proxies.get(i)));
            }
            expectedHistoryReferences.add(proxies.get(i).getHandshakeReference());
            expectedChannels.add(proxies.get(i).getDTO());
        }

        // Then
        Assert.assertThat(rootFolder.getChannels(), is(expectedChannels));
        Assert.assertThat(hostNode.getChannels(), is(expectedChannels));
        Assert.assertThat(handshakeFolder.getChannels(), is(expectedChannels));
        Assert.assertTrue(messagesFolder.getChannels().isEmpty());

        for (HistoryReference expectedRef : expectedHistoryReferences) {
            Assert.assertTrue(rootFolder.getHandshakeReferences().contains(expectedRef));
            Assert.assertTrue(hostNode.getHandshakeReferences().contains(expectedRef));
            Assert.assertTrue(handshakeFolder.getHandshakeReferences().contains(expectedRef));
            Assert.assertTrue(messagesFolder.getHandshakeReferences().isEmpty());
        }
    }

    @Test
    public void shouldGetAllHostNodes()
            throws URIException, DatabaseException, HttpMalformedHeaderException {
        // Given
        ArrayList<TreeNode<WebSocketContent>> expectedHostNodes = new ArrayList<>();
        WebSocketChannelDTO channel;
        for (int i = 0; i < 5; i++) {
            HistoryReference historyReference =
                    getMockHistoryReference(new URI("hostname_" + i, true));
            channel = getWebSocketChannelDTO(i, "hostname_" + i);
            WebSocketProxy proxy = getMockWebSocketProxy(historyReference, channel);

            // When
            HostFolderContent hostContent = new HostFolderContent(namer, proxy);
            WebSocketNode hostNode = new WebSocketNode(rootFolder, hostContent);
            WebSocketNode handshakeFolder =
                    new WebSocketNode(hostNode, new HandshakeFolderContent(namer));
            new WebSocketNode(handshakeFolder, new HandshakeContent(namer, proxy));
            expectedHostNodes.add(hostNode);
        }

        // Then
        Assert.assertThat(
                rootFolder.getHostNodes(rootFolder, new ArrayList<>()), is(expectedHostNodes));
    }

    @Test
    public void shouldGetChannelsAndHandshakesPerHost()
            throws DatabaseException, HttpMalformedHeaderException, URIException {

        // Given
        HashMap<TreeNode<WebSocketContent>, List<WebSocketChannelDTO>> expectedChannelMap =
                new HashMap<>();
        HashMap<TreeNode<WebSocketContent>, List<HistoryReference>> expectedHandshakeRefMap =
                new HashMap<>();

        WebSocketNode[] handshakeFolder = new WebSocketNode[2];
        WebSocketNode[] hostNode = new WebSocketNode[2];
        for (int i = 0; i < 10; i++) {
            HistoryReference historyReference =
                    getMockHistoryReference(new URI("hostname_" + i % 2, true));
            WebSocketChannelDTO channel =
                    getWebSocketChannelDTO(i, "hostname_" + i % 2, "hostname_" + i % 2 + "/#" + i);
            WebSocketProxy proxy = getMockWebSocketProxy(historyReference, channel);
            if (i < 2) {
                HostFolderContent hostContent = new HostFolderContent(namer, proxy);
                hostNode[i] = new WebSocketNode(rootFolder, hostContent);
                handshakeFolder[i] =
                        new WebSocketNode(hostNode[i], new HandshakeFolderContent(namer));
            }

            // When
            new WebSocketNode(handshakeFolder[i % 2], new HandshakeContent(namer, proxy));

            expectedChannelMap
                    .computeIfAbsent(hostNode[i % 2], t -> new ArrayList<>())
                    .add(channel);

            expectedHandshakeRefMap
                    .computeIfAbsent(hostNode[i % 2], t -> new ArrayList<>())
                    .add(historyReference);
        }

        System.out.println(rootFolder);

        // Then
        for (int i = 0; i < hostNode.length; i++) {
            List<WebSocketChannelDTO> channels =
                    rootFolder.getChannelsPerHost(rootFolder, new HashMap<>()).get(hostNode[i]);
            Collections.sort(channels);
            Assert.assertThat(channels, is(expectedChannelMap.get(hostNode[i])));
        }
    }
}
