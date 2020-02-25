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
import java.util.List;
import java.util.Objects;
import org.zaproxy.zap.extension.websocket.treemap.nodes.structural.TreeNode;

/**
 * This class and their sub-classes of it, stores the appropriate values, and perform the
 * appropriate functionality to be entries of a {@link TreeNode<WebSocketContent>}.
 */
public abstract class WebSocketContent implements NodeContent, Comparable<NodeContent> {

    protected String name;

    @Override
    public String getName() {
        return name;
    }

    /**
     * Returns the host in which the content exists.
     *
     * @param thisNode The tree node of the content.
     * @return The host node of this content.
     */
    TreeNode getTheHostNode(TreeNode thisNode) {
        List<TreeNode> hostNodes = getHostNodes(thisNode, new ArrayList<>());
        if (hostNodes == null || hostNodes.isEmpty()) {
            return null;
        }
        return hostNodes.get(0);
    }

    /**
     * This method is useful to be implemented when we want to sort the content in a specific depth.
     *
     * @param that The content is going to be compared with this object.
     * @return Negative values if is less than, zero then equal and positive then that object is
     *     greater than this object.
     */
    @Override
    public int compareTo(NodeContent that) {
        return this.getName().compareTo(that.getName());
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        WebSocketContent that = (WebSocketContent) o;
        return that.name.equals(this.name);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(name);
    }
}
