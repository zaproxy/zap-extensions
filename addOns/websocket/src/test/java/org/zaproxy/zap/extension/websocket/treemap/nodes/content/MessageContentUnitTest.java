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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.zaproxy.zap.extension.websocket.ExtensionWebSocket;
import org.zaproxy.zap.extension.websocket.WebSocketAddonTestUtils;
import org.zaproxy.zap.extension.websocket.WebSocketChannelDTO;
import org.zaproxy.zap.extension.websocket.WebSocketMessage;
import org.zaproxy.zap.extension.websocket.WebSocketMessageDTO;
import org.zaproxy.zap.extension.websocket.treemap.nodes.WebSocketNode;
import org.zaproxy.zap.extension.websocket.treemap.nodes.contents.HostFolderContent;
import org.zaproxy.zap.extension.websocket.treemap.nodes.contents.MessageContent;
import org.zaproxy.zap.extension.websocket.treemap.nodes.contents.RootContent;
import org.zaproxy.zap.extension.websocket.treemap.nodes.namers.WebSocketSimpleNodeNamer;
import org.zaproxy.zap.extension.websocket.treemap.nodes.structural.TreeNode;

class MessageContentUnitTest extends WebSocketAddonTestUtils {

    private WebSocketSimpleNodeNamer namer;
    private static URI defaultHostName;
    TreeNode root;

    @BeforeEach
    void setUp() throws Exception {
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
    void shouldMessagesBeEquals() {

        // Given
        WebSocketChannelDTO channel1 = getWebSocketChannelDTO(1, defaultHostName.toString());
        WebSocketChannelDTO channel2 = getWebSocketChannelDTO(2, defaultHostName.toString());

        WebSocketMessageDTO message1 =
                getWebSocketMessageDTO(channel1, WebSocketMessage.OPCODE_TEXT, true, "Test", 1);
        WebSocketMessageDTO message2 =
                getWebSocketMessageDTO(channel2, WebSocketMessage.OPCODE_TEXT, true, "Test", 2);

        // When
        MessageContent messageContent1 = new MessageContent(namer, message1);
        MessageContent messageContent2 = new MessageContent(namer, message2);

        // Then
        assertEquals(0, messageContent1.compareTo(messageContent2));
    }

    @Test
    void shouldMessageShouldBeGreater() {

        // Given
        WebSocketChannelDTO channel1 = getWebSocketChannelDTO(1, defaultHostName.toString());
        WebSocketChannelDTO channel2 = getWebSocketChannelDTO(2, defaultHostName.toString());

        WebSocketMessageDTO message1 =
                getWebSocketMessageDTO(channel1, WebSocketMessage.OPCODE_TEXT, true, "AAAAA", 1);
        WebSocketMessageDTO message2 =
                getWebSocketMessageDTO(channel2, WebSocketMessage.OPCODE_TEXT, true, "AAAAB", 2);

        // When
        MessageContent messageContent1 = new MessageContent(namer, message1);
        MessageContent messageContent2 = new MessageContent(namer, message2);

        // Then
        assertTrue(messageContent1.compareTo(messageContent2) < 0);
        assertTrue(messageContent2.compareTo(messageContent1) > 0);
    }

    @Test
    void shouldNotBeEqualWithDifferentDirection() {

        // Given
        WebSocketChannelDTO channel1 = getWebSocketChannelDTO(1, defaultHostName.toString());
        WebSocketChannelDTO channel2 = getWebSocketChannelDTO(2, defaultHostName.toString());

        WebSocketMessageDTO message1 =
                getWebSocketMessageDTO(channel1, WebSocketMessage.OPCODE_TEXT, true, "Test", 1);
        WebSocketMessageDTO message2 =
                getWebSocketMessageDTO(channel2, WebSocketMessage.OPCODE_TEXT, false, "Test", 1);

        // When
        MessageContent messageContent1 = new MessageContent(namer, message1);
        MessageContent messageContent2 = new MessageContent(namer, message2);

        // Then
        assertNotEquals(0, messageContent1.compareTo(messageContent2));
        assertNotEquals(0, messageContent2.compareTo(messageContent1));
    }

    @Test
    void shouldCloneBeTheSame() {

        // Given
        MessageContent messageContent =
                new MessageContent(
                        namer,
                        getWebSocketMessageDTO(
                                getWebSocketChannelDTO(1, defaultHostName.toString()),
                                WebSocketMessage.OPCODE_TEXT,
                                true,
                                "test",
                                1));

        // When
        MessageContent cloneContent = new MessageContent(messageContent);

        // Then
        assertEquals(0, messageContent.compareTo(cloneContent));
        assertEquals(0, cloneContent.compareTo(messageContent));
    }

    @Test
    void shouldGetHostNode() throws URIException, DatabaseException, HttpMalformedHeaderException {

        // Given
        URI hostUri1 = new URI("https", null, defaultHostName.toString(), -1, "/first");
        WebSocketChannelDTO channel =
                getWebSocketChannelDTO(1, defaultHostName.toString(), hostUri1.toString());
        TreeNode hostNode = new WebSocketNode(root, new HostFolderContent(namer, channel));

        TreeNode messageNode =
                new WebSocketNode(
                        hostNode,
                        new MessageContent(namer, getTextOutgoingMessage(channel, "Test", 1)));

        // When
        List<TreeNode> actualHostList = messageNode.getHostNodes(new ArrayList<>());

        // Then
        assertEquals(1, actualHostList.size());
        assertEquals(hostNode, actualHostList.get(0));
    }

    @Test
    void shouldGetMessagesPerHost()
            throws URIException, DatabaseException, HttpMalformedHeaderException {
        String[] hosts = {"hostname_1", "hostname_2"};
        ArrayList<TreeNode> hostNodes = new ArrayList<>();

        // Given
        for (int i = 0; i < 5; i++) {
            URI handshakeUri1 = new URI("https", null, hosts[i % 2], -1, "/sth");
            WebSocketChannelDTO channel =
                    getWebSocketChannelDTO(i, hosts[i % 2], handshakeUri1.toString());

            if (i < 2) {
                hostNodes.add(new WebSocketNode(root, new HostFolderContent(namer, channel)));
            }
            new WebSocketNode(
                    hostNodes.get(i % 2),
                    new MessageContent(
                            namer,
                            getWebSocketMessageDTO(
                                    getWebSocketChannelDTO(1, defaultHostName.toString()),
                                    WebSocketMessage.OPCODE_TEXT,
                                    false,
                                    "Test_" + i,
                                    i)));
        }

        // When
        List<WebSocketMessageDTO> messagesHost1 =
                root.getMessagesPerHost(new HashMap<>()).get(hostNodes.get(0));
        List<WebSocketMessageDTO> messagesHost2 =
                root.getMessagesPerHost(new HashMap<>()).get(hostNodes.get(1));

        // Then
        assertEquals(3, messagesHost1.size());
        assertEquals(2, messagesHost2.size());
    }
}
