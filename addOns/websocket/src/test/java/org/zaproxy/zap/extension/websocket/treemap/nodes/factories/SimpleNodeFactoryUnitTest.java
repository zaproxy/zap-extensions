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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import org.apache.commons.httpclient.URIException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.zaproxy.zap.extension.websocket.ExtensionWebSocket;
import org.zaproxy.zap.extension.websocket.WebSocketAddonTestUtils;
import org.zaproxy.zap.extension.websocket.WebSocketChannelDTO;
import org.zaproxy.zap.extension.websocket.WebSocketMessageDTO;
import org.zaproxy.zap.extension.websocket.treemap.nodes.NodesUtilities;
import org.zaproxy.zap.extension.websocket.treemap.nodes.contents.HostFolderContent;
import org.zaproxy.zap.extension.websocket.treemap.nodes.contents.MessageContent;
import org.zaproxy.zap.extension.websocket.treemap.nodes.namers.WebSocketSimpleNodeNamer;
import org.zaproxy.zap.extension.websocket.treemap.nodes.structural.TreeNode;
import org.zaproxy.zap.extension.websocket.utility.InvalidUtf8Exception;

class SimpleNodeFactoryUnitTest extends WebSocketAddonTestUtils {

    private NodeFactory nodeFactory;
    private WebSocketSimpleNodeNamer namer;

    @BeforeEach
    void setUp() throws Exception {
        setUpMessages();
        super.startWebSocketServer("localhost");
        namer = new WebSocketSimpleNodeNamer();
        nodeFactory = new SimpleNodeFactory(namer);
    }

    @Override
    protected void setUpMessages() {
        mockMessages(new ExtensionWebSocket());
    }

    @Test
    void shouldAddConnection()
            throws URIException, DatabaseException, HttpMalformedHeaderException {
        // Given
        WebSocketChannelDTO channel = getWebSocketChannelDTO(1, getServerUrl().toString());

        // When
        TreeNode hostNode = nodeFactory.getHostTreeNode(channel);

        // Then
        assertEquals(NodesUtilities.getHostName(channel), hostNode.getHost());
    }

    @Test
    void shouldNotAddExistingHost() throws DatabaseException, HttpMalformedHeaderException {
        // Given
        WebSocketChannelDTO channel1_1 = getWebSocketChannelDTO(1, "hostname_1");
        WebSocketChannelDTO channel2_1 = getWebSocketChannelDTO(2, "hostname_1");
        WebSocketChannelDTO channel3_2 = getWebSocketChannelDTO(3, "hostname_2");
        WebSocketChannelDTO channel4_3 = getWebSocketChannelDTO(4, "hostname_3");

        // When
        TreeNode hostNode_1_1 = nodeFactory.getHostTreeNode(channel1_1);
        TreeNode hostNode_2_1 = nodeFactory.getHostTreeNode(channel2_1);
        TreeNode hostNode_3_2 = nodeFactory.getHostTreeNode(channel3_2);
        TreeNode hostNode_4_3 = nodeFactory.getHostTreeNode(channel4_3);

        // Then
        assertEquals(hostNode_1_1, hostNode_2_1);
        assertNotEquals(hostNode_3_2, hostNode_2_1);
        assertNotEquals(hostNode_3_2, hostNode_4_3);
    }

    @Test
    void shouldAddMessagesUnderCorrectHostNode()
            throws DatabaseException, HttpMalformedHeaderException {
        // Given
        List<WebSocketChannelDTO> channels =
                channels(
                        getWebSocketChannelDTO(1, "hostname_1"),
                        getWebSocketChannelDTO(2, "hostname_2"));
        TreeNode host1 = nodeFactory.getHostTreeNode(channels.get(0));
        TreeNode host2 = nodeFactory.getHostTreeNode(channels.get(1));
        ArrayList<WebSocketMessageDTO> messages = new ArrayList<>();

        Comparator<WebSocketMessageDTO> comparator =
                (baseMessage, t1) -> {
                    try {
                        return baseMessage.getReadablePayload().compareTo(t1.getReadablePayload());
                    } catch (InvalidUtf8Exception ignored) {
                    }
                    return -1;
                };

        // When
        for (int i = 0; i < 5; i++) {
            messages.add(getTextOutgoingMessage(channels.get(i % 2), "TestMessage_" + i, i));
            nodeFactory.getMessageTreeNode(messages.get(i)).getMessage();
        }
        List<WebSocketMessageDTO> host1Messages =
                nodeFactory.getRoot().getMessagesPerHost(new HashMap<>()).get(host1);
        host1Messages.sort(comparator);
        List<WebSocketMessageDTO> host2Messages =
                nodeFactory.getRoot().getMessagesPerHost(new HashMap<>()).get(host2);
        host2Messages.sort(comparator);

        // Then
        assertEquals(host1Messages.get(0).getId(), messages.get(0).getId());
        assertEquals(host1Messages.get(1).getId(), messages.get(2).getId());
        assertEquals(host1Messages.get(2).getId(), messages.get(4).getId());

        assertEquals(host2Messages.get(0).getId(), messages.get(1).getId());
        assertEquals(host2Messages.get(1).getId(), messages.get(3).getId());
    }

    @Test
    void shouldUpdateMessageIfExists() throws DatabaseException, HttpMalformedHeaderException {
        // Given
        List<WebSocketChannelDTO> channels =
                channels(
                        getWebSocketChannelDTO(1, "hostname_A"),
                        getWebSocketChannelDTO(2, "hostname_A"));
        TreeNode hostNode = nodeFactory.getHostTreeNode(channels.get(0));

        // When
        nodeFactory.getMessageTreeNode(getTextOutgoingMessage(channels.get(0), "Message_1", 1));
        WebSocketMessageDTO expectedMessage =
                getTextOutgoingMessage(channels.get(1), "Message_1", 1);
        nodeFactory.getMessageTreeNode(expectedMessage);

        // Then
        WebSocketMessageDTO actualMessage =
                nodeFactory.getRoot().getMessagesPerHost(new HashMap<>()).get(hostNode).get(0);
        assertEquals(expectedMessage.getId(), actualMessage.getId());
        assertEquals(expectedMessage.getChannel(), actualMessage.getChannel());
    }

    @Test
    void shouldGetRightPosition() throws DatabaseException, HttpMalformedHeaderException {
        // Given
        WebSocketChannelDTO channelA = getWebSocketChannelDTO(1, "Hostname_A");
        WebSocketChannelDTO channelB = getWebSocketChannelDTO(2, "Hostname_B");
        WebSocketChannelDTO channelC = getWebSocketChannelDTO(3, "Hostname_C");

        nodeFactory.getHostTreeNode(channelA);
        nodeFactory.getHostTreeNode(channelB);

        List<WebSocketMessageDTO> messages =
                messages(
                        getTextOutgoingMessage(channelA, "Message_A_1", 1),
                        getTextOutgoingMessage(channelA, "Message_A_2", 2),
                        getTextOutgoingMessage(channelA, "Message_A_3", 3));

        for (WebSocketMessageDTO message : messages) {
            nodeFactory.getMessageTreeNode(message);
        }

        List<TreeNode> hostNodes = new ArrayList<>();
        nodeFactory.getRoot().getHostNodes(hostNodes);

        // When & Then
        assertEquals(0, nodeFactory.getRoot().getPosition(new HostFolderContent(namer, channelA)));
        assertEquals(1, nodeFactory.getRoot().getPosition(new HostFolderContent(namer, channelB)));
        assertEquals(-3, nodeFactory.getRoot().getPosition(new HostFolderContent(namer, channelC)));
        assertEquals(0, hostNodes.get(0).getPosition(new MessageContent(namer, messages.get(0))));
        assertEquals(1, hostNodes.get(0).getPosition(new MessageContent(namer, messages.get(1))));
        assertEquals(2, hostNodes.get(0).getPosition(new MessageContent(namer, messages.get(2))));
        assertEquals(
                -4,
                hostNodes
                        .get(0)
                        .getPosition(
                                new MessageContent(
                                        namer,
                                        getTextOutgoingMessage(channelA, "Message_A_4", 4))));
        assertEquals(
                -1,
                hostNodes
                        .get(1)
                        .getPosition(
                                new MessageContent(
                                        namer,
                                        getTextOutgoingMessage(channelB, "Message_B_1", 1))));
    }
}
