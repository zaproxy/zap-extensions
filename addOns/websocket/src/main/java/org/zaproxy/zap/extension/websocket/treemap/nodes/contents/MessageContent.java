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
 * This content stores a {@link WebSocketMessageDTO}. WebSocket Messages with same host, direction
 * and payload stored under a specific message in same MessageContent.
 */
public class MessageContent extends WebSocketContent {

    private WebSocketMessageDTO webSocketMessage;

    public MessageContent(WebSocketNodeNamer namer, WebSocketMessageDTO message) {
        this.webSocketMessage = new WebSocketMessageDTO();
        message.copyInto(this.webSocketMessage);
        name = namer.getName(this);
    }

    public MessageContent(MessageContent that) {
        this.webSocketMessage = new WebSocketMessageDTO();
        that.getMessage().copyInto(this.webSocketMessage);
        this.name = that.getName();
    }

    @Override
    public WebSocketMessageDTO getMessage() {
        return webSocketMessage;
    }

    /**
     * This function is responsible to identify if two WebSocket Messages are greater, Firstly,
     * {@link WebSocketMessageDTO#payload} are compared lexicographically. If they are equals, then
     * check the direction. The outgoing messages precedes the incoming ones.
     *
     * @param that The content is going to be compared with this object.
     * @return the value 0 if messages are lexicographically equal and with the same direction; a
     *     value less than 0 if this message is lexicographically less than the message argument or
     *     this message is incoming and message argument is outgoing; and a value greater than 0 if
     *     this message is lexicographically greater than the message argument or this message is
     *     outgoing and message argument is incoming.
     */
    @Override
    public int compareTo(NodeContent that) {
        int compareResult;
        if (that instanceof MessageContent) {
            try {
                compareResult =
                        this.getMessage()
                                .getReadablePayload()
                                .compareTo(that.getMessage().getReadablePayload());
                if (compareResult == 0
                        && !this.getMessage().isOutgoing.equals(that.getMessage().isOutgoing)) {
                    compareResult = that.getMessage().isOutgoing ? 1 : -1;
                }
            } catch (InvalidUtf8Exception ignored) {
                compareResult = super.compareTo(that);
            }
        } else {
            compareResult = super.compareTo(that);
        }
        return compareResult;
    }

    public NodeContent replaceValues(
            WebSocketNodeNamer namer, WebSocketMessageDTO webSocketMessage) {
        this.webSocketMessage = webSocketMessage;
        this.name = namer.getName(this);
        return this;
    }

    @Override
    public boolean equals(Object that) {
        return super.equals(that) && this.compareTo((NodeContent) that) == 0;
    }

    @Override
    public List<TreeNode> getHostNodes(TreeNode thisNode, List<TreeNode> hostNodesList) {
        if (thisNode.isRoot() || !thisNode.hasContent()) return null;

        return thisNode.getParent().getHostNodes(hostNodesList);
    }

    @Override
    public HashMap<TreeNode, List<WebSocketMessageDTO>> getMessagesPerHost(
            TreeNode thisNode, HashMap<TreeNode, List<WebSocketMessageDTO>> messageMap) {
        TreeNode hostNode = getTheHostNode(thisNode);
        if (hostNode == null || getMessage() == null) return messageMap;

        messageMap.computeIfAbsent(hostNode, k -> new ArrayList<>()).add(getMessage());

        return messageMap;
    }

    @Override
    public NodeContent update(NodeContent nodeContent) {
        this.webSocketMessage = new WebSocketMessageDTO();
        nodeContent.getMessage().copyInto(this.webSocketMessage);
        return this;
    }
}
