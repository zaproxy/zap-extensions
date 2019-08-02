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
package org.zaproxy.zap.extension.websocket.treemap.nodes.contents;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import org.zaproxy.zap.extension.websocket.WebSocketMessageDTO;
import org.zaproxy.zap.extension.websocket.treemap.nodes.namers.WebSocketNodeNamer;
import org.zaproxy.zap.extension.websocket.treemap.nodes.structural.TreeNode;
import org.zaproxy.zap.extension.websocket.utility.InvalidUtf8Exception;

/**
 * This content stores a {@link WebSocketMessageDTO}. WebSocket Messages with same host, opcode,
 * direction and payload stored under a specific message in same MessageContent.
 */
public class MessageContent extends WebSocketContent {

    private WebSocketMessageDTO webSocketMessage;

    public MessageContent(WebSocketNodeNamer namer, WebSocketMessageDTO message) {
        this.webSocketMessage = message;
        name = namer.getName(this);
    }

    private MessageContent(MessageContent that) {
        this.webSocketMessage = that.getMessage();
        this.name = that.getName();
    }

    @Override
    public WebSocketMessageDTO getMessage() {
        return webSocketMessage;
    }

    /**
     * This function is responsible to identify if two WebSocket Messages are equal.
     *
     * @param that The content is going to be compared with this object.
     * @return negative values if they have different {@link WebSocketMessageDTO#payloadLength},
     *     {@link WebSocketMessageDTO#isOutgoing} or {@link WebSocketMessageDTO#opcode}. If the
     *     above properties are equal them negative values means that the compering {@link
     *     WebSocketMessageDTO#payload} is lower in lexicographic ordering. Zero means that there
     *     are equal and positive values means that it is greater in lexicographic ordering
     */
    @Override
    public int compareTo(WebSocketContent that) {
        if (that instanceof MessageContent) {
            if (!this.getMessage().payloadLength.equals(that.getMessage().payloadLength)) return -1;
            if (this.getMessage().isOutgoing != that.getMessage().isOutgoing) return -1;
            if (!this.getMessage().opcode.equals(that.getMessage().opcode)) return -1;
            try {
                return this.getMessage()
                        .getReadablePayload()
                        .compareTo(that.getMessage().getReadablePayload());
            } catch (InvalidUtf8Exception e) {
                // Do nothing
            }
        }
        return super.compareTo(that);
    }

    @Override
    public MessageContent clone() {
        return new MessageContent(this);
    }

    public WebSocketContent replaceValues(
            WebSocketNodeNamer namer, WebSocketMessageDTO webSocketMessage) {
        this.webSocketMessage = webSocketMessage;
        name = namer.getName(this);
        return this;
    }

    @Override
    public boolean equals(Object that) {
        return super.equals(that) && this.compareTo((WebSocketContent) that) == 0;
    }

    @Override
    public List<TreeNode<WebSocketContent>> getHostNodes(
            TreeNode<WebSocketContent> thisNode, List<TreeNode<WebSocketContent>> hostNodesList) {
        if (thisNode.isRoot() || !thisNode.hasContent()) return null;

        return thisNode.getParent().getHostNodes(thisNode.getParent(), hostNodesList);
    }

    @Override
    public HashMap<TreeNode<WebSocketContent>, List<WebSocketMessageDTO>> getMessagesPerHost(
            TreeNode<WebSocketContent> thisNode,
            HashMap<TreeNode<WebSocketContent>, List<WebSocketMessageDTO>> messageMap) {
        TreeNode<WebSocketContent> hostNode = getTheHostNode(thisNode);
        if (hostNode == null || getMessage() == null) return messageMap;

        messageMap.computeIfAbsent(hostNode, k -> new ArrayList<>()).add(getMessage());

        return messageMap;
    }
}
