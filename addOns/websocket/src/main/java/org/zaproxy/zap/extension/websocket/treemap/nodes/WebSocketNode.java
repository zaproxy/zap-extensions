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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import org.parosproxy.paros.model.HistoryReference;
import org.zaproxy.zap.extension.websocket.WebSocketChannelDTO;
import org.zaproxy.zap.extension.websocket.WebSocketMessageDTO;
import org.zaproxy.zap.extension.websocket.treemap.nodes.contents.WebSocketContent;
import org.zaproxy.zap.extension.websocket.treemap.nodes.structural.TreeNode;

public class WebSocketNode extends TreeNode<WebSocketContent> {

    public WebSocketNode(TreeNode<WebSocketContent> parent, WebSocketContent content) {
        super(parent, content);
    }

    /**
     * Add children in appropriate position. Using {@link Comparable#compareTo(Object)} to match the
     * right position. If {@link Comparable#compareTo(Object)} means that the node already exists
     * and return the existing node.
     *
     * @param newChild is going to be added.
     * @return new child or the existing one if already exists.
     */
    @Override
    public TreeNode<WebSocketContent> addChild(TreeNode<WebSocketContent> newChild) {
        if (super.isLeaf()) {
            return super.addChild(newChild);
        }

        int i = 0;
        for (; i < super.getChildren().size(); i++) {
            if (getChildren().get(i).compareTo(newChild) == 0) {
                return null;
            } else if (getChildren().get(i).compareTo(newChild) > 0) {
                return super.addChild(i, newChild);
            }
        }
        return super.addChild(i, newChild);
    }

    @Override
    public WebSocketMessageDTO getMessage() {
        return content.getMessage();
    }

    @Override
    public String getHost() {
        return content.getHost();
    }

    @Override
    public List<TreeNode<WebSocketContent>> getHostNodes(
            TreeNode<WebSocketContent> thisNode, List<TreeNode<WebSocketContent>> hostNodesList) {
        return thisNode.getContent().getHostNodes(thisNode, hostNodesList);
    }

    @Override
    public HashMap<TreeNode<WebSocketContent>, List<WebSocketMessageDTO>> getMessagesPerHost(
            TreeNode<WebSocketContent> thisNode,
            HashMap<TreeNode<WebSocketContent>, List<WebSocketMessageDTO>> messageMap) {
        return thisNode.getContent().getMessagesPerHost(thisNode, messageMap);
    }

    @Override
    public HashMap<TreeNode<WebSocketContent>, List<WebSocketChannelDTO>> getChannelsPerHost(
            TreeNode<WebSocketContent> thisNode,
            HashMap<TreeNode<WebSocketContent>, List<WebSocketChannelDTO>> channelsMap) {
        return thisNode.getContent().getChannelsPerHost(thisNode, channelsMap);
    }

    @Override
    public HashMap<TreeNode<WebSocketContent>, List<HistoryReference>>
            getHandshakesReferencesPerHost(
                    TreeNode<WebSocketContent> thisNode,
                    HashMap<TreeNode<WebSocketContent>, List<HistoryReference>> refMap) {
        return thisNode.getContent().getHandshakesReferencesPerHost(thisNode, refMap);
    }

    @Override
    public List<HistoryReference> getHandshakeReferences() {
        return iterateOverLeafToAddAll(
                this, WebSocketNode::getHandshakeReferences, new ArrayList<>());
    }

    @Override
    public List<WebSocketChannelDTO> getChannels() {
        return iterateOverLeafToAddAll(this, WebSocketNode::getChannels, new ArrayList<>());
    }

    List<WebSocketMessageDTO> getMessages() {
        return iterateOverLeaf(this, WebSocketNode::getMessage, new ArrayList<>());
    }

    private static WebSocketMessageDTO getMessage(TreeNode<WebSocketContent> t) {
        return t.getContent().getMessage();
    }

    private static List<WebSocketChannelDTO> getChannels(TreeNode<WebSocketContent> t) {
        return t.getContent().getChannels();
    }

    private static List<HistoryReference> getHandshakeReferences(TreeNode<WebSocketContent> t) {
        return t.getContent().getHandshakeReferences();
    }
}
