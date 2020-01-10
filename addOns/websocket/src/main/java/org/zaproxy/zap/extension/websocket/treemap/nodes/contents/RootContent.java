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
import org.zaproxy.zap.extension.websocket.WebSocketMessageDTO;
import org.zaproxy.zap.extension.websocket.treemap.nodes.namers.WebSocketNodeNamer;
import org.zaproxy.zap.extension.websocket.treemap.nodes.structural.TreeNode;

/**
 * This content is responsible for the Root node, meaning that contains the entries and the
 * appropriate function to be a Root.
 */
public class RootContent extends WebSocketContent {

    public RootContent(WebSocketNodeNamer namer) {
        name = namer.getName(this);
    }

    /**
     * Iterates over it's children to retrieve the host folder nodes.
     *
     * @param thisNode The root node.
     * @param hostNodesList List with the host nodes.
     * @return List with the host nodes.
     */
    @Override
    public List<TreeNode> getHostNodes(TreeNode thisNode, List<TreeNode> hostNodesList) {
        thisNode.applyToChildren(t -> t.getHostNodes(hostNodesList));
        return hostNodesList;
    }

    /**
     * Iterates over it's children to retrieve messages per host node folder.
     *
     * @param thisNode The node which calls the method.
     * @param messageMap The map where it should store the values.
     * @return The map with messages per host node folder.
     */
    @Override
    public HashMap<TreeNode, List<WebSocketMessageDTO>> getMessagesPerHost(
            TreeNode thisNode, HashMap<TreeNode, List<WebSocketMessageDTO>> messageMap) {
        thisNode.applyToChildren(t -> t.getMessagesPerHost(messageMap));
        return messageMap;
    }
}
