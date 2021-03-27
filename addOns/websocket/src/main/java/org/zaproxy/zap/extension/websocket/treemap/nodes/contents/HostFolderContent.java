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
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.zaproxy.zap.extension.websocket.WebSocketChannelDTO;
import org.zaproxy.zap.extension.websocket.WebSocketMessageDTO;
import org.zaproxy.zap.extension.websocket.treemap.nodes.NodesUtilities;
import org.zaproxy.zap.extension.websocket.treemap.nodes.namers.WebSocketNodeNamer;
import org.zaproxy.zap.extension.websocket.treemap.nodes.structural.WebSocketNodeInterface;

/**
 * This content is responsible for the Host Folder Node, meaning that stores the appropriate
 * information about a specific host. In addition, it contains the appropriate method to retrieve
 * valuable information which are stored in the tree.
 */
public class HostFolderContent extends WebSocketContent {

    private String host;
    private WebSocketChannelDTO channel;

    public HostFolderContent(WebSocketNodeNamer namer, WebSocketChannelDTO channel)
            throws DatabaseException, HttpMalformedHeaderException {
        this.channel = new WebSocketChannelDTO();
        this.host = NodesUtilities.getHostName(channel);
        this.name = namer.getName(this);
        channel.copyInto(this.channel);
    }

    public HostFolderContent(HostFolderContent that) {
        this.channel = new WebSocketChannelDTO();
        this.host = that.getHost();
        this.name = that.getName();
        that.channel.copyInto(this.getChannel());
    }

    public HostFolderContent replaceValues(WebSocketNodeNamer namer, WebSocketChannelDTO channel)
            throws DatabaseException, HttpMalformedHeaderException {
        this.host = NodesUtilities.getHostName(channel);
        this.name = namer.getName(this);
        channel.copyInto(this.channel);
        return this;
    }

    @Override
    public WebSocketChannelDTO getChannel() {
        return channel;
    }

    @Override
    public HashMap<WebSocketNodeInterface, List<WebSocketMessageDTO>> getMessagesPerHost(
            WebSocketNodeInterface thisNode,
            HashMap<WebSocketNodeInterface, List<WebSocketMessageDTO>> messageMap) {

        if (thisNode.isLeaf()) return messageMap;

        thisNode.applyToChildren(t -> t.getMessagesPerHost(messageMap));
        return messageMap;
    }

    @Override
    public int compareTo(NodeContent that) {
        int compareResult;
        if (that instanceof HostFolderContent) {
            compareResult = this.getHost().compareTo(that.getHost());
        } else {
            compareResult = super.compareTo(that);
        }
        return compareResult;
    }

    @Override
    public boolean equals(Object that) {
        if (that instanceof HostFolderContent) {
            return this.getHost().equals(((HostFolderContent) that).getHost());
        }
        return false;
    }

    @Override
    public String getHost() {
        return host;
    }

    @Override
    public List<WebSocketNodeInterface> getHostNodes(
            WebSocketNodeInterface thisNode, List<WebSocketNodeInterface> hostNodesList) {
        hostNodesList.add(thisNode);
        return hostNodesList;
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(host);
    }

    @Override
    public NodeContent update(NodeContent nodeContent) {
        this.channel = new WebSocketChannelDTO();
        nodeContent.getChannel().copyInto(this.channel);
        return this;
    }
}
