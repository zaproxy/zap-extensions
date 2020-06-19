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
import org.zaproxy.zap.extension.websocket.WebSocketMessageDTO;
import org.zaproxy.zap.extension.websocket.treemap.nodes.contents.NodeContent;
import org.zaproxy.zap.extension.websocket.treemap.nodes.structural.TreeNode;

public class WebSocketNode extends TreeNode {

    public WebSocketNode(TreeNode parent, NodeContent content) {
        super(parent, content);
    }

    public WebSocketNode(TreeNode parent, int position, NodeContent content) {
        super(parent, position, content);
    }

    @Override
    public NodeContent getContent() {
        return content;
    }

    @Override
    public String getName() {
        return content.getName();
    }

    @Override
    public TreeNode updateContent(NodeContent content) {
        this.content = this.content.update(content);
        return this;
    }

    @Override
    public WebSocketMessageDTO getMessage() {
        return content.getMessage();
    }

    public List<WebSocketMessageDTO> getMessages() {
        return iterateOverLeaf(this, TreeNode::getMessage, new ArrayList<>());
    }

    @Override
    public String getHost() {
        return content.getHost();
    }

    @Override
    public List<TreeNode> getHostNodes(List<TreeNode> hostNodesList) {
        return this.getContent().getHostNodes(this, hostNodesList);
    }

    @Override
    public HashMap<TreeNode, List<WebSocketMessageDTO>> getMessagesPerHost(
            HashMap<TreeNode, List<WebSocketMessageDTO>> messageMap) {
        return this.getContent().getMessagesPerHost(this, messageMap);
    }
}
