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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.zap.extension.websocket.WebSocketMessage;
import org.zaproxy.zap.extension.websocket.WebSocketObserver;
import org.zaproxy.zap.extension.websocket.WebSocketProxy;
import org.zaproxy.zap.extension.websocket.db.WebSocketStorage;
import org.zaproxy.zap.extension.websocket.treemap.nodes.factories.NodeFactory;
import org.zaproxy.zap.extension.websocket.treemap.nodes.factories.SimpleNodeFactory;
import org.zaproxy.zap.extension.websocket.treemap.nodes.namers.WebSocketNodeNamer;
import org.zaproxy.zap.extension.websocket.treemap.nodes.structural.TreeNode;

public class WebSocketTreeMap implements WebSocketObserver {

    private static final Logger LOGGER = LogManager.getLogger(WebSocketTreeMap.class);

    private static final int OBSERVER_ORDER = WebSocketStorage.WEBSOCKET_OBSERVING_ORDER + 1;

    /** Constructs nodes according to the appropriate Tree Structure */
    private NodeFactory nodeFactory;

    /** True if server proxies should be ignored */
    private boolean isServerModeIgnored = true;

    public WebSocketTreeMap(WebSocketNodeNamer namer) {
        nodeFactory = new SimpleNodeFactory(namer);
    }

    /** Adding a WebSocket Message in the Tree Map. */
    private synchronized TreeNode addMessage(WebSocketMessage webSocketMessage) {

        TreeNode result = null;

        if (!shouldIgnoreMode(webSocketMessage.getProxyMode())) {

            result = nodeFactory.getMessageTreeNode(webSocketMessage.getDTO());

            LOGGER.debug(nodeFactory.getRoot());
        }

        return result;
    }

    /**
     * Add a new Host in the Tree Structure.
     *
     * @param proxy the Connecting proxy.
     * @return the new Host Node or the existing one.
     */
    private synchronized TreeNode addConnection(WebSocketProxy proxy) {

        TreeNode result = null;

        if (!shouldIgnoreMode(proxy.getMode())) {

            try {
                result = nodeFactory.getHostTreeNode(proxy.getDTO());
            } catch (Exception e) {
                LOGGER.info(
                        "Can't get Handshake message to add a new connection to WebSocket Tree Map");
            }

            LOGGER.debug(nodeFactory.getRoot());
        }

        return result;
    }

    private boolean shouldIgnoreMode(WebSocketProxy.Mode mode) {
        return isServerModeIgnored && mode == WebSocketProxy.Mode.SERVER;
    }

    public boolean isServerModeIgnored() {
        return isServerModeIgnored;
    }

    public void setServerModeIgnored(boolean serverModeIgnored) {
        isServerModeIgnored = serverModeIgnored;
    }

    @Override
    public int getObservingOrder() {
        return OBSERVER_ORDER;
    }

    @Override
    public boolean onMessageFrame(int channelId, WebSocketMessage message) {
        addMessage(message);
        return true;
    }

    @Override
    public void onStateChange(WebSocketProxy.State state, WebSocketProxy proxy) {
        if (state == WebSocketProxy.State.CONNECTING) {
            addConnection(proxy);
        }
    }
}
