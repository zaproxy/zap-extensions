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

public abstract class WebSocketNodeAbstract implements WebSocketNodeInterface {

    protected NodeContent content;
    private WebSocketNodeInterface parent;
    private List<WebSocketNodeInterface> children;
    private int index;

    protected WebSocketNodeAbstract(WebSocketNodeInterface parent, NodeContent content) {
        this.parent = parent;
        this.content = content;
        if (parent != null) {
            this.index = this.parent.addChild(this);
        }
    }

    protected WebSocketNodeAbstract(
            WebSocketNodeInterface parent, int position, NodeContent content) {
        this.parent = parent;
        this.content = content;
        if (parent != null) {
            this.parent.addChild(position, this);
            index = position;
        }
    }

    public boolean hasContent() {
        return content != null;
    }

    public boolean isRoot() {
        return (parent == null);
    }

    public WebSocketNodeInterface getParent() {
        return parent;
    }

    public WebSocketNodeInterface getChildAt(int pos) {
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

    public List<WebSocketNodeInterface> getChildren() {
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
    public int addChild(WebSocketNodeInterface newChild) {
        int index;
        if (isLeaf()) {
            index = 0;
        } else {
            index = Collections.binarySearch(getChildren(), newChild);
            if (index < 0) {
                index = Math.abs(index) - 1;
            }
        }
        addChild(index, newChild);
        return index;
    }

    @Override
    public void addChild(int index, WebSocketNodeInterface child) {
        getChildren().add(index, child);
    }

    @Override
    public int getIndex() {
        return index;
    }

    public int getPosition(NodeContent nodeContent) {
        return Collections.binarySearch(getChildren(), new WebSocketNode(null, nodeContent));
    }

    @Override
    public String toString() {
        return getString(new StringBuilder(), this, 0).toString();
    }

    public StringBuilder getString(
            StringBuilder stringBuilder, WebSocketNodeInterface root, int depth) {

        for (int i = 0; i < depth; i++) {
            stringBuilder.append("\t");
        }
        stringBuilder.append(root.getName()).append("\n");

        for (WebSocketNodeInterface webSocketNode : root.getChildren()) {
            root.getString(stringBuilder, webSocketNode, depth + 1);
        }
        return stringBuilder;
    }

    @Override
    public int compareTo(WebSocketNodeInterface webSocketNode) {
        return this.getContent().compareTo(webSocketNode.getContent());
    }

    @Override
    public int hashCode() {
        return content.hashCode();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        WebSocketNodeAbstract that = (WebSocketNodeAbstract) o;
        if (!this.parent.equals(that.parent)) return false;
        if (!that.hasContent()) return false;
        if (!that.getContent().equals(content)) return false;
        return true;
    }

    public <T> WebSocketNodeInterface getChildrenWhen(
            Function<WebSocketNodeInterface, T> function, T when) {
        for (WebSocketNodeInterface child : this.getChildren()) {
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
     * @param <T> type that the function returns and list stores.
     * @param root this node.
     * @param function the leaf is going to be performed.
     * @param list is going to store the result of the function.
     * @return list with results of the leaf nodes.
     */
    public <T> List<T> iterateOverLeaf(
            WebSocketNodeInterface root,
            Function<WebSocketNodeInterface, T> function,
            List<T> list) {
        if (root.isLeaf()) {
            if (function.apply(root) != null) {
                list.add(function.apply(root));
            }
        } else {
            for (WebSocketNodeInterface child : root.getChildren()) {
                list = iterateOverLeaf(child, function, list);
            }
        }
        return list;
    }
    /**
     * This is like {@link WebSocketNodeInterface#iterateOverLeaf(WebSocketNodeInterface, Function,
     * List)} but it is used when the function returns a batch of results.
     *
     * @param <T> that the function returns.
     * @param <C> that the list stores
     * @param root this node.
     * @param function is going to be performed.
     * @param list where the result are stored.
     * @return list with results of the leaf nodes.
     */
    public <T extends Collection<C>, C> List<C> iterateOverLeafToAddAll(
            WebSocketNodeInterface root,
            Function<WebSocketNodeInterface, T> function,
            List<C> list) {
        if (root.isLeaf()) {
            if (function.apply(root) != null) {
                list.addAll(function.apply(root));
            }
        } else {
            for (WebSocketNodeInterface child : root.getChildren()) {
                list = iterateOverLeafToAddAll(child, function, list);
            }
        }
        return list;
    }

    public void applyToChildren(Consumer<WebSocketNodeInterface> consumer) {
        for (WebSocketNodeInterface child : this.getChildren()) {
            consumer.accept(child);
        }
    }

    public abstract NodeContent getContent();

    public abstract String getName();

    public abstract WebSocketNodeInterface updateContent(NodeContent content);

    public abstract WebSocketMessageDTO getMessage();

    public abstract String getHost();

    public abstract List<WebSocketNodeInterface> getHostNodes(
            List<WebSocketNodeInterface> hostNodesList);

    public abstract HashMap<WebSocketNodeInterface, List<WebSocketMessageDTO>> getMessagesPerHost(
            HashMap<WebSocketNodeInterface, List<WebSocketMessageDTO>> messageMap);
}
