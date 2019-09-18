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
package org.zaproxy.zap.extension.websocket.treemap.nodes.factories;

import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.zaproxy.zap.extension.websocket.WebSocketMessageDTO;
import org.zaproxy.zap.extension.websocket.WebSocketProxy;
import org.zaproxy.zap.extension.websocket.treemap.nodes.contents.WebSocketContent;
import org.zaproxy.zap.extension.websocket.treemap.nodes.structural.TreeNode;

public interface NodeFactory {

    /**
     * Adds WebSocket Message to tree structure.
     *
     * @param message is going to be inserted in the structure
     * @return the {@link TreeNode<WebSocketContent>} with the appropriate message content.
     */
    TreeNode<WebSocketContent> getMessageTreeNode(WebSocketMessageDTO message);

    /**
     * Adds a new WebSocket Channel in the structure.
     *
     * @param proxy the proxy which intercepting the WebSocket Connection.
     * @return the handshake node either the existing or the new one.
     * @throws DatabaseException when can't retrieve {@link
     *     org.parosproxy.paros.model.HistoryReference} for Handshake Message from Database.
     * @throws HttpMalformedHeaderException when Handshake Message in Malformed,
     */
    TreeNode<WebSocketContent> getHandshakeTreeNode(WebSocketProxy proxy)
            throws DatabaseException, HttpMalformedHeaderException;

    /** @return the Root of Tree Structure */
    TreeNode<WebSocketContent> getRoot();
}
