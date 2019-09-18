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
package org.zaproxy.zap.extension.websocket.treemap;

import org.apache.log4j.Logger;
import org.zaproxy.zap.extension.websocket.WebSocketMessage;
import org.zaproxy.zap.extension.websocket.WebSocketMessageDTO;
import org.zaproxy.zap.extension.websocket.WebSocketObserver;
import org.zaproxy.zap.extension.websocket.WebSocketProxy;
import org.zaproxy.zap.extension.websocket.treemap.nodes.contents.WebSocketContent;
import org.zaproxy.zap.extension.websocket.treemap.nodes.factories.NodeFactory;
import org.zaproxy.zap.extension.websocket.treemap.nodes.factories.SimpleNodeFactory;
import org.zaproxy.zap.extension.websocket.treemap.nodes.namers.WebSocketNodeNamer;
import org.zaproxy.zap.extension.websocket.treemap.nodes.structural.TreeNode;

public class WebSocketTreeMap implements WebSocketObserver {

    private static final Logger LOGGER = Logger.getLogger(WebSocketTreeMap.class);

    private static final int OBSERVER_ORDER = 30;

    private NodeFactory nodeFactory;

    public WebSocketTreeMap(WebSocketNodeNamer namer) {
        nodeFactory = new SimpleNodeFactory(namer);
    }

    /** Adding a WebSocket Message in the Tree Map. */
    protected synchronized TreeNode<WebSocketContent> addMessage(
            WebSocketMessageDTO webSocketMessage) {
        TreeNode<WebSocketContent> result = nodeFactory.getMessageTreeNode(webSocketMessage);
        LOGGER.debug(nodeFactory.getRoot());
        return result;
    }

    protected synchronized TreeNode<WebSocketContent> addConnection(WebSocketProxy webSocketProxy) {
        TreeNode<WebSocketContent> result = null;
        try {
            result = nodeFactory.getHandshakeTreeNode(webSocketProxy);
        } catch (Exception e) {
            LOGGER.warn("Can't add connection to the Tree Map", e);
        }
        LOGGER.debug(nodeFactory.getRoot());
        return result;
    }

    @Override
    public int getObservingOrder() {
        return OBSERVER_ORDER;
    }

    @Override
    public boolean onMessageFrame(int channelId, WebSocketMessage message) {
        addMessage(message.getDTO());
        return true;
    }

    @Override
    public void onStateChange(WebSocketProxy.State state, WebSocketProxy proxy) {
        if (state == WebSocketProxy.State.CONNECTING) {
            addConnection(proxy);
        }
    }
}
