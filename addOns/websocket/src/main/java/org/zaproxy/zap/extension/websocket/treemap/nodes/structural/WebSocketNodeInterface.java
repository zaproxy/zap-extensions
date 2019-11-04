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

import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.function.Consumer;
import java.util.function.Function;
import org.zaproxy.zap.extension.websocket.WebSocketMessageDTO;
import org.zaproxy.zap.extension.websocket.treemap.nodes.contents.NodeContent;

public interface WebSocketNodeInterface extends Comparable<WebSocketNodeInterface> {

    boolean hasContent();

    boolean isRoot();

    WebSocketNodeInterface getParent();

    WebSocketNodeInterface getChildAt(int pos);

    int addChild(WebSocketNodeInterface newChild);

    void addChild(int index, WebSocketNodeInterface child);

    boolean isLeaf();

    int getIndex();

    List<WebSocketNodeInterface> getChildren();

    int getPosition(NodeContent nodeContent);

    <T> WebSocketNodeInterface getChildrenWhen(
            Function<WebSocketNodeInterface, T> function, T when);

    <T> List<T> iterateOverLeaf(
            WebSocketNodeInterface root,
            Function<WebSocketNodeInterface, T> function,
            List<T> list);

    <T extends Collection<C>, C> List<C> iterateOverLeafToAddAll(
            WebSocketNodeInterface root,
            Function<WebSocketNodeInterface, T> function,
            List<C> list);

    void applyToChildren(Consumer<WebSocketNodeInterface> consumer);

    NodeContent getContent();

    String getName();

    StringBuilder getString(StringBuilder stringBuilder, WebSocketNodeInterface root, int depth);

    WebSocketNodeInterface updateContent(NodeContent content);

    WebSocketMessageDTO getMessage();

    String getHost();

    List<WebSocketNodeInterface> getHostNodes(List<WebSocketNodeInterface> hostNodesList);

    HashMap<WebSocketNodeInterface, List<WebSocketMessageDTO>> getMessagesPerHost(
            HashMap<WebSocketNodeInterface, List<WebSocketMessageDTO>> messageMap);
}
