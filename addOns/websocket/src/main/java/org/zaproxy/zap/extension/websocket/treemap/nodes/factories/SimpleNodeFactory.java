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

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.zaproxy.zap.extension.websocket.WebSocketChannelDTO;
import org.zaproxy.zap.extension.websocket.WebSocketMessageDTO;
import org.zaproxy.zap.extension.websocket.WebSocketProxy;
import org.zaproxy.zap.extension.websocket.treemap.nodes.WebSocketNode;
import org.zaproxy.zap.extension.websocket.treemap.nodes.contents.*;
import org.zaproxy.zap.extension.websocket.treemap.nodes.namers.WebSocketNodeNamer;
import org.zaproxy.zap.extension.websocket.treemap.nodes.structural.TreeNode;

/**
 * This Factory create nodes in order to create the following structure: <code>
 * <br>
 * |- RootNode {@link RootContent}<br>
 * &nbsp;|- HostNode {@link HostFolderContent} <br>
 * &nbsp;&nbsp;|- HandshakeFolderNode {@link HandshakeFolderContent} <br>
 * &nbsp;&nbsp;&nbsp;|- HandshakeNode {@link HandshakeContent} <br>
 * &nbsp;&nbsp;|- MessageFolderNode {@link MessageFolderContent} with {@link Type#MESSAGES} <br>
 * &nbsp;&nbsp;&nbsp;|- MessageNode {@link MessageContent} <br>
 * &nbsp;&nbsp;|- HeartbeatFolderNode {@link MessageFolderContent} with {@link Type#HEARTBEAT} <br>
 * &nbsp;&nbsp;&nbsp;|- MessageNode {@link MessageContent} <br>
 * &nbsp;&nbsp;|- CloseFolderNode {@link MessageFolderContent} with {@link Type#CLOSE} <br>
 * &nbsp;&nbsp;&nbsp;|- MessageNode {@link MessageContent} <br>
 * </code>
 */
public class SimpleNodeFactory implements NodeFactory {

    private WebSocketNodeNamer namer;
    private TreeNode<WebSocketContent> root;

    private HandshakeContent handshakeContentPrototype = null;
    private HandshakeFolderContent handshakeFolderPrototype = null;
    private MessageContent messageContentPrototype = null;
    private HostFolderContent hostContentPrototype = null;
    private MessageFolderContent messageFolderContentPrototype = null;

    public SimpleNodeFactory(WebSocketNodeNamer namer) {
        this.namer = namer;
        this.root = getRoot();
    }

    @Override
    public TreeNode<WebSocketContent> getRoot() {
        if (root == null) {
            root = new WebSocketNode(null, new RootContent(namer));
        }
        return root;
    }

    /**
     * Adds two layers, if not exists, under Host Node ({@link HostFolderContent}). A
     * {@link MessageFolderContent} layer and under that a {@link MessageContent} leaf.
     * Example:
     *
     * <code>
     * <br>
     * |- HostNode <br>
     * &nbsp;|- Message Folder <i>(add if not exist)<i/> <br>
     * &nbsp;&nbsp;|- Message Node <i>(add if not exist)<i/> <br>
     * <code/>
     *
     * @param message is going to be inserted in the structure
     * @return the Message Node
     */
    @Override
    public TreeNode<WebSocketContent> getMessageTreeNode(WebSocketMessageDTO message) {

        TreeNode<WebSocketContent> hostNode = getHostFolder(getRoot(), message.channel);
        if (hostNode == null) return null;

        TreeNode<WebSocketContent> messagesFolder =
                addLayerIfNotExist(hostNode, getMessageFolderPrototype(message));
        TreeNode<WebSocketContent> messageNode =
                addLayerIfNotExist(messagesFolder, getMessageContentPrototype(message));

        return messageNode;
    }

    /**
     * Add tree layers, if not exists, under the Root node {@link RootContent}. A {@link
     * HostFolderContent} is added if not exists in the structure. Under that a {@link
     * HandshakeFolderContent} is going to be added if not exists. Finally, adds the {@link
     * HandshakeContent} as leaf if note exists. Example: <code>
     * <br>
     * |- RootNode <br>
     * &nbsp;|- HostNode <i>(add if not exists)</i> <br>
     * &nbsp;&nbsp;|- HandshakeFolderNode <i>(add if not exists)</i> <br>
     * &nbsp;&nbsp;&nbsp;|- HandshakeNode <i>(add if not exists)</i> <br>
     * </code>
     *
     * @param proxy the proxy which intercepting the WebSocket Connection.
     * @return the Hanshake Leaf node
     */
    @Override
    public TreeNode<WebSocketContent> getHandshakeTreeNode(WebSocketProxy proxy)
            throws DatabaseException, HttpMalformedHeaderException {

        TreeNode<WebSocketContent> hostFolder =
                addLayerIfNotExist(getRoot(), getHostContentPrototype(proxy));
        TreeNode<WebSocketContent> handshakeFolder =
                addHandshakeFolderNode(hostFolder, getHandshakeFolderPrototype());

        return addLayerIfNotExist(handshakeFolder, getHandshakeContentPrototype(proxy));
    }

    private TreeNode<WebSocketContent> getHostFolder(
            TreeNode<WebSocketContent> root, WebSocketChannelDTO channel) {

        HashMap<TreeNode<WebSocketContent>, List<WebSocketChannelDTO>> channelsMap =
                root.getChannelsPerHost(root, new HashMap<>());

        for (Map.Entry<TreeNode<WebSocketContent>, List<WebSocketChannelDTO>> entry :
                channelsMap.entrySet()) {
            if (entry.getValue().contains(channel)) {
                return entry.getKey();
            }
        }
        return null;
    }

    private TreeNode<WebSocketContent> addHandshakeFolderNode(
            TreeNode<WebSocketContent> root, WebSocketContent content) {

        int pos = root.getPosition(content);
        if (pos < 0) {
            return new WebSocketNode(root, content.clone());
        } else {
            TreeNode<WebSocketContent> handshakeNode = root.getChildAt(pos);
            handshakeNode.getContent().addToContent(content);
            return handshakeNode;
        }
    }

    private TreeNode<WebSocketContent> addLayerIfNotExist(
            TreeNode<WebSocketContent> root, WebSocketContent content) {
        int pos = root.getPosition(content);
        return (pos < 0) ? new WebSocketNode(root, content.clone()) : root.getChildAt(pos);
    }

    private HandshakeContent getHandshakeContentPrototype(WebSocketProxy proxy) {
        if (handshakeContentPrototype == null) {
            handshakeContentPrototype = new HandshakeContent(namer, proxy);
        } else {
            handshakeContentPrototype = handshakeContentPrototype.replaceValues(namer, proxy);
        }
        return handshakeContentPrototype;
    }

    private HostFolderContent getHostContentPrototype(WebSocketProxy proxy)
            throws DatabaseException, HttpMalformedHeaderException {
        if (hostContentPrototype == null) {
            hostContentPrototype = new HostFolderContent(namer, proxy);
        } else {
            hostContentPrototype = hostContentPrototype.replaceValues(namer, proxy);
        }
        return hostContentPrototype;
    }

    private HandshakeFolderContent getHandshakeFolderPrototype() {
        if (handshakeFolderPrototype == null) {
            handshakeFolderPrototype = new HandshakeFolderContent(namer);
        }
        return handshakeFolderPrototype;
    }

    private MessageFolderContent getMessageFolderPrototype(WebSocketMessageDTO message) {
        if (messageFolderContentPrototype == null) {
            messageFolderContentPrototype = new MessageFolderContent(namer, message.opcode);
        } else {
            messageFolderContentPrototype =
                    messageFolderContentPrototype.replaceValues(namer, message.opcode);
        }
        return messageFolderContentPrototype;
    }

    private MessageContent getMessageContentPrototype(WebSocketMessageDTO message) {
        if (messageContentPrototype == null) {
            messageContentPrototype = new MessageContent(namer, message);
        } else {
            messageContentPrototype.replaceValues(namer, message);
        }
        return messageContentPrototype;
    }
}
