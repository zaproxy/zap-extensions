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

import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.zaproxy.zap.extension.websocket.WebSocketChannelDTO;
import org.zaproxy.zap.extension.websocket.WebSocketMessageDTO;
import org.zaproxy.zap.extension.websocket.treemap.nodes.NodesUtilities;
import org.zaproxy.zap.extension.websocket.treemap.nodes.WebSocketNode;
import org.zaproxy.zap.extension.websocket.treemap.nodes.contents.HostFolderContent;
import org.zaproxy.zap.extension.websocket.treemap.nodes.contents.MessageContent;
import org.zaproxy.zap.extension.websocket.treemap.nodes.contents.RootContent;
import org.zaproxy.zap.extension.websocket.treemap.nodes.namers.WebSocketNodeNamer;
import org.zaproxy.zap.extension.websocket.treemap.nodes.structural.TreeNode;

/**
 * This Factory constructs nodes and arrange them as following:
 *
 * <pre>
 * +-------------+
 * |     Root    |
 * +-+-----------+
 *   |     +---------------+
 *   +-----+  Host Node 1  |
 *   |     +---------------+
 *   |      | +-----------------+
 *   |      +-+    Message      |
 *   |        |      Nodes      |
 *   |        +-----------------+
 *   |     +---------------+
 *   +-----+  Host Node 2  |
 *         +---------------+
 *          | +-----------------+
 *          +-+    Message      |
 *            |      Nodes      |
 *            +-----------------+
 * </pre>
 */
public class SimpleNodeFactory implements NodeFactory {

    private WebSocketNodeNamer namer;
    private WebSocketNode root;
    private MessageContent messageContentPrototype = null;
    private HostFolderContent hostContentPrototype = null;

    public SimpleNodeFactory(WebSocketNodeNamer namer) {
        this.namer = namer;
        this.root = getRoot();
    }

    @Override
    public WebSocketNode getRoot() {
        if (root == null) {
            root = new WebSocketNode(null, new RootContent(namer));
        }
        return root;
    }

    @Override
    public TreeNode getMessageTreeNode(WebSocketMessageDTO message) {

        TreeNode hostNode = null;
        try {
            hostNode =
                    root.getChildrenWhen(
                            TreeNode::getHost, NodesUtilities.getHostName(message.channel));
        } catch (Exception ignored) {
        }
        if (hostNode == null) return null;

        MessageContent content = getMessageContentPrototype(message);

        int pos = hostNode.getPosition(content);

        return (pos < 0)
                ? new WebSocketNode(hostNode, Math.abs(pos) - 1, new MessageContent(content))
                : hostNode.getChildAt(pos).updateContent(content);
    }

    @Override
    public TreeNode getHostTreeNode(WebSocketChannelDTO channel)
            throws DatabaseException, HttpMalformedHeaderException {

        HostFolderContent content = getHostContentPrototype(channel);

        int pos = root.getPosition(content);
        return (pos < 0)
                ? new WebSocketNode(root, Math.abs(pos) - 1, new HostFolderContent(content))
                : root.getChildAt(pos);
    }

    private HostFolderContent getHostContentPrototype(WebSocketChannelDTO channel)
            throws DatabaseException, HttpMalformedHeaderException {
        if (hostContentPrototype == null) {
            hostContentPrototype = new HostFolderContent(namer, channel);
        } else {
            hostContentPrototype = hostContentPrototype.replaceValues(namer, channel);
        }
        return hostContentPrototype;
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
