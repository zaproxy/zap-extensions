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

import java.util.HashMap;
import java.util.List;
import java.util.Objects;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.zaproxy.zap.extension.websocket.WebSocketChannelDTO;
import org.zaproxy.zap.extension.websocket.WebSocketMessageDTO;
import org.zaproxy.zap.extension.websocket.WebSocketProxy;
import org.zaproxy.zap.extension.websocket.treemap.nodes.NodesUtilities;
import org.zaproxy.zap.extension.websocket.treemap.nodes.namers.WebSocketNodeNamer;
import org.zaproxy.zap.extension.websocket.treemap.nodes.structural.TreeNode;

/**
 * This content is responsible fot the Host Folder Node, meaning tha stores the appropriate
 * information about a specific host. In addition, has contains the appropriate method to retrieve
 * valuable information which is store in the tree.
 */
public class HostFolderContent extends WebSocketContent {

    private String hostName;

    /**
     * @param namer The {@link WebSocketNodeNamer} to name the content.
     * @param proxy The proxy which establishes the specific host.
     * @throws DatabaseException if it is unable to retrieve {@link HistoryReference} of the
     *     Handshake Message.
     * @throws HttpMalformedHeaderException if the Handshake Message is malformed.
     */
    public HostFolderContent(WebSocketNodeNamer namer, WebSocketProxy proxy)
            throws DatabaseException, HttpMalformedHeaderException {
        hostName =
                NodesUtilities.getHostName(
                        proxy.getHandshakeReference().getHttpMessage(), proxy.getDTO());

        name = namer.getName(this);
    }

    private HostFolderContent(HostFolderContent that) {
        this.hostName = that.getHost();
        this.name = that.getName();
    }

    public HostFolderContent replaceValues(WebSocketNodeNamer namer, WebSocketProxy proxy)
            throws DatabaseException, HttpMalformedHeaderException {
        hostName =
                NodesUtilities.getHostName(
                        proxy.getHandshakeReference().getHttpMessage(), proxy.getDTO());

        name = namer.getName(this);
        return this;
    }

    @Override
    public HashMap<TreeNode<WebSocketContent>, List<WebSocketMessageDTO>> getMessagesPerHost(
            TreeNode<WebSocketContent> thisNode,
            HashMap<TreeNode<WebSocketContent>, List<WebSocketMessageDTO>> messageMap) {

        if (thisNode.isLeaf()) return messageMap;

        thisNode.applyToChildren(t -> t.getMessagesPerHost(t, messageMap));
        return messageMap;
    }

    @Override
    public HashMap<TreeNode<WebSocketContent>, List<WebSocketChannelDTO>> getChannelsPerHost(
            TreeNode<WebSocketContent> thisNode,
            HashMap<TreeNode<WebSocketContent>, List<WebSocketChannelDTO>> channelsMap) {
        if (thisNode.isLeaf()) return channelsMap;

        thisNode.applyToChildren(t -> t.getChannelsPerHost(t, channelsMap));
        return channelsMap;
    }

    @Override
    public HashMap<TreeNode<WebSocketContent>, List<HistoryReference>>
            getHandshakesReferencesPerHost(
                    TreeNode<WebSocketContent> thisNode,
                    HashMap<TreeNode<WebSocketContent>, List<HistoryReference>> refMap) {
        if (thisNode.isLeaf()) return refMap;
        thisNode.iterateOverChildren(t -> t.getHandshakesReferencesPerHost(t, refMap));
        return refMap;
    }

    @Override
    public boolean equals(Object that) {
        return super.equals(that) && this.hostName.equals(((HostFolderContent) that).getHost());
    }

    @Override
    public String getHost() {
        return hostName;
    }

    @Override
    public List<TreeNode<WebSocketContent>> getHostNodes(
            TreeNode<WebSocketContent> thisNode, List<TreeNode<WebSocketContent>> hostNodesList) {
        hostNodesList.add(thisNode);
        return hostNodesList;
    }

    @Override
    public HostFolderContent clone() {
        return new HostFolderContent(this);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(hostName);
    }
}
