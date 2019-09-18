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
import org.parosproxy.paros.model.HistoryReference;
import org.zaproxy.zap.extension.websocket.WebSocketChannelDTO;
import org.zaproxy.zap.extension.websocket.WebSocketProxy;
import org.zaproxy.zap.extension.websocket.treemap.nodes.namers.WebSocketNodeNamer;
import org.zaproxy.zap.extension.websocket.treemap.nodes.structural.TreeNode;

/** This content stores the {@link HistoryReference} for the handshake messages. */
public class HandshakeContent extends WebSocketContent {

    private List<HistoryReference> handshakeReferences;
    private List<WebSocketChannelDTO> channels;

    /**
     * @param namer is used to name the content.
     * @param webSocketProxy proxy which intercepts the WebSocket Communication.
     */
    public HandshakeContent(WebSocketNodeNamer namer, WebSocketProxy webSocketProxy) {
        handshakeReferences = new ArrayList<>();
        channels = new ArrayList<>();

        handshakeReferences.add(webSocketProxy.getHandshakeReference());
        channels.add(webSocketProxy.getDTO());
        this.name = namer.getName(this);
    }

    private HandshakeContent(HandshakeContent that) {
        this.handshakeReferences = new ArrayList<>(that.getHandshakeReferences());
        this.channels = new ArrayList<>(that.getChannels());
        this.name = that.getName();
    }

    public HandshakeContent replaceValues(WebSocketNodeNamer namer, WebSocketProxy proxy) {
        handshakeReferences.clear();
        channels.clear();

        handshakeReferences.add(proxy.getHandshakeReference());
        channels.add(proxy.getDTO());

        this.name = namer.getName(this);
        return this;
    }

    /**
     * This method is used to add new {@link HistoryReference} and {@link WebSocketChannelDTO} to
     * the existing host content.
     *
     * @param webSocketContent The content with the additional information.
     * @return
     */
    @Override
    public WebSocketContent addToContent(WebSocketContent webSocketContent) {
        handshakeReferences.addAll(webSocketContent.getHandshakeReferences());
        channels.addAll(webSocketContent.getChannels());
        return this;
    }

    @Override
    public List<HistoryReference> getHandshakeReferences() {
        return handshakeReferences;
    }

    @Override
    public HandshakeContent clone() {
        return new HandshakeContent(this);
    }

    @Override
    public List<TreeNode<WebSocketContent>> getHostNodes(
            TreeNode<WebSocketContent> thisNode, List<TreeNode<WebSocketContent>> hostNodesList) {
        if (thisNode.getParent() != null && thisNode.getParent().getContent() != null) {
            return thisNode.getParent().getHostNodes(thisNode.getParent(), hostNodesList);
        }
        return null;
    }

    @Override
    public HashMap<TreeNode<WebSocketContent>, List<WebSocketChannelDTO>> getChannelsPerHost(
            TreeNode<WebSocketContent> thisNode,
            HashMap<TreeNode<WebSocketContent>, List<WebSocketChannelDTO>> channelsMap) {
        TreeNode<WebSocketContent> hostNode = getTheHostNode(thisNode);
        if (hostNode == null || getChannels() == null || getChannels().isEmpty()) {
            return channelsMap;
        }

        channelsMap.computeIfAbsent(hostNode, k -> new ArrayList<>()).addAll(getChannels());
        return channelsMap;
    }

    @Override
    public HashMap<TreeNode<WebSocketContent>, List<HistoryReference>>
            getHandshakesReferencesPerHost(
                    TreeNode<WebSocketContent> thisNode,
                    HashMap<TreeNode<WebSocketContent>, List<HistoryReference>> refMap) {
        TreeNode<WebSocketContent> hostNode = getTheHostNode(thisNode);
        if (hostNode == null
                || getHandshakeReferences() == null
                || getHandshakeReferences().isEmpty()) {
            return refMap;
        }

        refMap.computeIfAbsent(hostNode, k -> new ArrayList<>());
        refMap.get(hostNode).addAll(getHandshakeReferences());
        return refMap;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        return this.compareTo((HandshakeContent) o) == 0;
    }

    @Override
    public int hashCode() {
        return channels.get(0).id;
    }

    @Override
    public List<WebSocketChannelDTO> getChannels() {
        return channels;
    }
}
