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

import java.util.*;
import java.util.function.Consumer;
import java.util.function.Function;
import org.zaproxy.zap.extension.websocket.treemap.nodes.contents.NodeContent;
import org.zaproxy.zap.utils.Pair;

public abstract class TreeNode<E extends NodeContent & Comparable<E>>
        implements Comparable<TreeNode<E>>, NodeContent {

    protected E content;
    protected TreeNode<E> parent;
    protected LinkedList<TreeNode<E>> children;

    protected TreeNode(TreeNode<E> parent, E content) {
        this.parent = parent;
        this.content = content;
        if (parent != null) {
            this.parent.addChild(this);
        }
    }

    public boolean hasContent() {
        return content != null;
    }

    public boolean isRoot() {
        return (parent == null);
    }

    public TreeNode<E> getParent() {
        return parent;
    }

    public LinkedList<TreeNode<E>> getChildren() {
        if (children == null) {
            children = new LinkedList<>();
        }
        return children;
    }

    public TreeNode<E> getChildAt(int pos) {
        if (isLeaf() || pos > getChildren().size()) {
            return null;
        }
        return children.get(pos);
    }

    public boolean isLeaf() {
        if (children != null) {
            return children.isEmpty();
        }
        return true;
    }

    public TreeNode<E> addChild(TreeNode<E> child) {
        if (!getChildren().contains(child)) {
            children.add(child);
            return child;
        }
        return null;
    }

    public TreeNode<E> addChild(int at, TreeNode<E> child) {
        if (!getChildren().contains(child)) {
            children.add(at, child);
            return child;
        }
        return null;
    }

    public int getPosition(E content) {
        if (isLeaf()) {
            return -1;
        }
        int i = 0;
        for (; i < getChildren().size(); i++) {
            if (getChildren().get(i).getContent().compareTo(content) == 0) {
                return i;
            }
        }
        return -1;
    }

    public E getContent() {
        return content;
    }

    public String getName() {
        return content.getName();
    }

    /** Applies a {@link Consumer} to this node's children */
    public void applyToChildren(Consumer<TreeNode<E>> consumer) {
        for (TreeNode<E> child : this.getChildren()) {
            consumer.accept(child);
        }
    }

    /**
     * Iterate over the child of this node, perform a {@link Function} and add the result in a
     * {@link List}
     *
     * @param function to perform
     * @param <T> that the function returns
     * @return list with the values that every child return by perform the function
     */
    public <T> List<T> iterateOverChildren(Function<TreeNode<E>, T> function) {
        List<T> list = new ArrayList<>();
        for (TreeNode<E> child : this.getChildren()) {
            list.add(function.apply(child));
        }
        return list;
    }

    /**
     * If this is a leaf then perform the function. In not transmit the request to this node's
     * children. The result of the function is stored at the list.
     *
     * @param root this node.
     * @param function the leaf is going to performed.
     * @param list is going to store the result of the function.
     * @param <T> that the function returns and list stores.
     * @return list with results of the leaf nodes.
     */
    protected <T> List<T> iterateOverLeaf(
            TreeNode<E> root, Function<TreeNode<E>, T> function, List<T> list) {
        if (root.isLeaf()) {
            if (function.apply(root) != null) {
                list.add(function.apply(root));
            }
        } else {
            for (TreeNode<E> child : root.getChildren()) {
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
    protected <T extends Collection<C>, C> List<C> iterateOverLeafToAddAll(
            TreeNode<E> root, Function<TreeNode<E>, T> function, List<C> list) {
        if (root.isLeaf()) {
            if (function.apply(root) != null) {
                list.addAll(function.apply(root));
            }
        } else {
            for (TreeNode<E> child : root.getChildren()) {
                list = iterateOverLeafToAddAll(child, function, list);
            }
        }
        return list;
    }

    @Override
    public String toString() {
        StringBuilder stringBuilder = new StringBuilder();
        int currentDepth;
        TreeNode<E> currentNode;
        Pair<TreeNode<E>, Integer> currentPair;
        Iterator<TreeNode<E>> childrenIterator;
        Stack<Pair<TreeNode<E>, Integer>> webSocketTreeNodeStack = new Stack<>();

        webSocketTreeNodeStack.push(new Pair<>(this, 0));

        while (!webSocketTreeNodeStack.empty()) { // Depth First
            currentPair = webSocketTreeNodeStack.pop();
            currentNode = currentPair.first;
            currentDepth = currentPair.second;

            for (int i = 0; i < currentDepth; i++) {
                stringBuilder.append("\t");
            }

            stringBuilder.append("|- " + currentNode.getName() + "\n");
            childrenIterator = currentNode.getChildren().iterator();
            while (childrenIterator.hasNext()) {
                webSocketTreeNodeStack.push(new Pair<>(childrenIterator.next(), currentDepth + 1));
            }
        }
        return stringBuilder.toString();
    }

    @Override
    public int compareTo(TreeNode<E> treeNode) {
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
        TreeNode<?> that = (TreeNode<?>) o;
        if (!this.parent.equals(that.parent)) return false;
        if (!that.hasContent()) return false;
        if (!that.getContent().equals(content)) return false;
        return true;
    }
}
