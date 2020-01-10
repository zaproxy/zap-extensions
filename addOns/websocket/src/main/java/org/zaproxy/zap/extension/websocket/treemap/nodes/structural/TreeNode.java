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
package org.zaproxy.zap.extension.websocket.treemap.nodes.structural;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.function.Consumer;
import java.util.function.Function;
import org.zaproxy.zap.extension.websocket.WebSocketMessageDTO;
import org.zaproxy.zap.extension.websocket.treemap.nodes.WebSocketNode;
import org.zaproxy.zap.extension.websocket.treemap.nodes.contents.NodeContent;

public abstract class TreeNode implements Comparable<TreeNode> {

    protected NodeContent content;
    private TreeNode parent;
    private List<TreeNode> children;

    protected TreeNode(TreeNode parent, NodeContent content) {
        this.parent = parent;
        this.content = content;
        if (parent != null) {
            this.parent.addChild(this);
        }
    }

    protected TreeNode(TreeNode parent, int position, NodeContent content) {
        this.parent = parent;
        this.content = content;
        if (parent != null) {
            this.parent.addChild(position, this);
        }
    }

    public boolean hasContent() {
        return content != null;
    }

    public boolean isRoot() {
        return (parent == null);
    }

    public TreeNode getParent() {
        return parent;
    }

    public TreeNode getChildAt(int pos) {
        if (isLeaf() || pos > getChildren().size()) {
            return null;
        }
        return getChildren().get(pos);
    }

    public boolean isLeaf() {
        if (getChildren() != null) {
            return getChildren().isEmpty();
        }
        return true;
    }

    public List<TreeNode> getChildren() {
        if (children == null) {
            children = new ArrayList<>();
        }
        return children;
    }

    /**
     * Add children in appropriate position. Using {@link Comparable#compareTo(Object)} to match the
     * right position. If {@link Comparable#compareTo(Object)} means that the node already exists
     * and return the existing node.
     *
     * @param newChild is going to be added.
     */
    private void addChild(TreeNode newChild) {
        if (isLeaf()) {
            addChild(0, newChild);
            return;
        }

        int position = Collections.binarySearch(getChildren(), newChild);
        if (position < 0) {
            addChild(Math.abs(position) - 1, newChild);
        }
    }

    private void addChild(int at, TreeNode child) {
        getChildren().add(at, child);
    }

    public int getPosition(NodeContent nodeContent) {
        return Collections.binarySearch(getChildren(), new WebSocketNode(null, nodeContent));
    }

    @Override
    public String toString() {
        return getString(new StringBuilder(), this, 0).toString();
    }

    private StringBuilder getString(StringBuilder stringBuilder, TreeNode root, int depth) {

        for (int i = 0; i < depth; i++) {
            stringBuilder.append("\t");
        }
        stringBuilder.append(root.getName()).append("\n");

        for (TreeNode treeNode : root.getChildren()) {
            root.getString(stringBuilder, treeNode, depth + 1);
        }
        return stringBuilder;
    }

    @Override
    public int compareTo(TreeNode treeNode) {
        return this.getContent().compareTo(treeNode.getContent());
    }

    @Override
    public int hashCode() {
        return content.hashCode();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TreeNode that = (TreeNode) o;
        if (!this.parent.equals(that.parent)) return false;
        if (!that.hasContent()) return false;
        if (!that.getContent().equals(content)) return false;
        return true;
    }

    public <T> TreeNode getChildrenWhen(Function<TreeNode, T> function, T when) {
        for (TreeNode child : this.getChildren()) {
            if (function.apply(child).equals(when)) {
                return child;
            }
        }
        return null;
    }

    /**
     * If this is a leaf then perform the function. If not, it transmits the request to this node's
     * children. The result of the function is stored at the list.
     *
     * @param root this node.
     * @param function the leaf is going to be performed.
     * @param list is going to store the result of the function.
     * @param <T> type that the function returns and list stores.
     * @return list with results of the leaf nodes.
     */
    public <T> List<T> iterateOverLeaf(
            TreeNode root, Function<TreeNode, T> function, List<T> list) {
        if (root.isLeaf()) {
            if (function.apply(root) != null) {
                list.add(function.apply(root));
            }
        } else {
            for (TreeNode child : root.getChildren()) {
                list = iterateOverLeaf(child, function, list);
            }
        }
        return list;
    }
    /**
     * This is like {@link TreeNode#iterateOverLeaf(TreeNode, Function, List)} but it is used when
     * the function returns a batch of results.
     *
     * @param root this node.
     * @param function is going to be performed.
     * @param list where the result are stored.
     * @param <T> that the function returns.
     * @param <C> that the list stores
     * @return list with results of the leaf nodes.
     */
    public <T extends Collection<C>, C> List<C> iterateOverLeafToAddAll(
            TreeNode root, Function<TreeNode, T> function, List<C> list) {
        if (root.isLeaf()) {
            if (function.apply(root) != null) {
                list.addAll(function.apply(root));
            }
        } else {
            for (TreeNode child : root.getChildren()) {
                list = iterateOverLeafToAddAll(child, function, list);
            }
        }
        return list;
    }

    public void applyToChildren(Consumer<TreeNode> consumer) {
        for (TreeNode child : this.getChildren()) {
            consumer.accept(child);
        }
    }

    public abstract NodeContent getContent();

    public abstract String getName();

    public abstract TreeNode updateContent(NodeContent content);

    public abstract WebSocketMessageDTO getMessage();

    public abstract String getHost();

    public abstract List<TreeNode> getHostNodes(List<TreeNode> hostNodesList);

    public abstract HashMap<TreeNode, List<WebSocketMessageDTO>> getMessagesPerHost(
            HashMap<TreeNode, List<WebSocketMessageDTO>> messageMap);
}
