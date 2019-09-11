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
import org.zaproxy.zap.extension.websocket.treemap.nodes.structural.TreeNode;

public interface NodeContent extends Comparable<NodeContent> {

    /** @return the name of the content. */
    String getName();

    /** @return the host name if need be. */
    default WebSocketMessageDTO getMessage() {
        return null;
    }

    /** @return the host name if need be. */
    default String getHost() {
        return null;
    }

    /**
     * Returns the host in which the content exists.
     *
     * @param thisNode The tree node of the content.
     * @param hostNodesList The list where it should store the Host Nodes.
     * @return The host node of this content.
     */
    List<TreeNode> getHostNodes(TreeNode thisNode, List<TreeNode> hostNodesList);

    /**
     * This method is used to traverse the tree in which the contents exists. So as to get messages
     * per host. This method should be implemented by the children class as well, to traverse
     * appropriate the tree. The following code should be used as default, meaning that just returns
     * the list as it is.
     *
     * @param thisNode The node which calls the method.
     * @param messageMap The map where it should store the values.
     * @return The map with the additional values.
     */
    default HashMap<TreeNode, List<WebSocketMessageDTO>> getMessagesPerHost(
            TreeNode thisNode, HashMap<TreeNode, List<WebSocketMessageDTO>> messageMap) {
        return messageMap;
    }

    default NodeContent update(NodeContent nodeContent) {
        return this;
    }
}
