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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.ArrayList;
import java.util.List;
import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.zaproxy.zap.extension.websocket.ExtensionWebSocket;
import org.zaproxy.zap.extension.websocket.WebSocketAddonTestUtils;
import org.zaproxy.zap.extension.websocket.WebSocketChannelDTO;
import org.zaproxy.zap.extension.websocket.WebSocketMessage;
import org.zaproxy.zap.extension.websocket.WebSocketMessageDTO;
import org.zaproxy.zap.extension.websocket.treemap.nodes.contents.HostFolderContent;
import org.zaproxy.zap.extension.websocket.treemap.nodes.contents.MessageContent;
import org.zaproxy.zap.extension.websocket.treemap.nodes.contents.RootContent;
import org.zaproxy.zap.extension.websocket.treemap.nodes.namers.WebSocketSimpleNodeNamer;
import org.zaproxy.zap.extension.websocket.treemap.nodes.structural.TreeNode;

class WebSocketNodesUnitTest extends WebSocketAddonTestUtils {

    private WebSocketNode rootFolder;
    private WebSocketSimpleNodeNamer namer;
    private static URI defaultHostName;

    @BeforeEach
    void setUp() throws Exception {
        setUpMessages();

        namer = new WebSocketSimpleNodeNamer();
        rootFolder = new WebSocketNode(null, new RootContent(namer));
        defaultHostName = new URI("hostname", true);
    }

    @Override
    protected void setUpMessages() {
        mockMessages(new ExtensionWebSocket());
    }

    @Test
    void shouldAddParentsAndChildren() throws DatabaseException, HttpMalformedHeaderException {

        // Given
        WebSocketChannelDTO channel = getWebSocketChannelDTO(1, defaultHostName.toString());

        // When
        WebSocketNode hostNode =
                new WebSocketNode(rootFolder, new HostFolderContent(namer, channel));

        WebSocketNode messageNode =
                new WebSocketNode(
                        hostNode, new MessageContent(namer, getTextOutgoingMessage("TestMessage")));

        // Then
        assertEquals(rootFolder.getChildren().get(0), hostNode);
        assertEquals(hostNode.getParent(), rootFolder);
        assertEquals(hostNode.getChildren().get(0), messageNode);
    }

    @Test
    void shouldGetContent() throws DatabaseException, HttpMalformedHeaderException {
        // Given
        WebSocketChannelDTO channel = getWebSocketChannelDTO(1, defaultHostName.toString());
        WebSocketMessageDTO message = getTextOutgoingMessage(channel, "TestMessage", 1);

        // When
        HostFolderContent hostContent = new HostFolderContent(namer, channel);
        WebSocketNode hostNode = new WebSocketNode(rootFolder, hostContent);

        WebSocketNode messageNode = new WebSocketNode(hostNode, new MessageContent(namer, message));

        // Then
        assertEquals(messageNode.getMessage().getId(), message.getId());
    }

    @Test
    void shouldGetMessages() throws DatabaseException, HttpMalformedHeaderException {
        // Given
        WebSocketChannelDTO channel = getWebSocketChannelDTO(1, defaultHostName.toString());

        List<WebSocketMessageDTO> expectedMessages =
                messages(
                        getWebSocketMessageDTO(
                                channel, WebSocketMessage.OPCODE_TEXT, false, "Message_1", 1),
                        getWebSocketMessageDTO(
                                channel, WebSocketMessage.OPCODE_TEXT, false, "Message_2", 2),
                        getWebSocketMessageDTO(
                                channel, WebSocketMessage.OPCODE_TEXT, false, "Message_3", 3));

        HostFolderContent hostContent = new HostFolderContent(namer, channel);
        WebSocketNode hostNode = new WebSocketNode(rootFolder, hostContent);

        for (WebSocketMessageDTO message : expectedMessages) {
            new WebSocketNode(hostNode, new MessageContent(namer, message));
        }

        // When
        List<WebSocketMessageDTO> messagesFromRoot = rootFolder.getMessages();
        List<WebSocketMessageDTO> messagesFromHost = hostNode.getMessages();

        // Then
        for (int i = 0; i < expectedMessages.size(); i++) {
            assertEquals(expectedMessages.get(i).getId(), messagesFromRoot.get(i).getId());
            assertEquals(expectedMessages.get(i).getId(), messagesFromHost.get(i).getId());
        }
    }

    @Test
    void shouldGetAllHostNodes() throws DatabaseException, HttpMalformedHeaderException {
        // Given
        ArrayList<TreeNode> expectedHostNodes = new ArrayList<>();
        WebSocketChannelDTO channel;
        for (int i = 0; i < 5; i++) {
            channel = getWebSocketChannelDTO(i, "hostname_" + i);

            // When
            HostFolderContent hostContent = new HostFolderContent(namer, channel);
            WebSocketNode hostNode = new WebSocketNode(rootFolder, hostContent);
            expectedHostNodes.add(hostNode);
        }

        // Then
        assertThat(rootFolder.getHostNodes(new ArrayList<>()), is(expectedHostNodes));
    }
}
