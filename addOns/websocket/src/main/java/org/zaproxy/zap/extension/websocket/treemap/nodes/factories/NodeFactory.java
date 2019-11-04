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
import org.zaproxy.zap.extension.websocket.WebSocketChannelDTO;
import org.zaproxy.zap.extension.websocket.WebSocketMessageDTO;
import org.zaproxy.zap.extension.websocket.treemap.nodes.WebSocketNodeWrapper;
import org.zaproxy.zap.extension.websocket.treemap.nodes.contents.NodeContent;
import org.zaproxy.zap.extension.websocket.treemap.nodes.structural.WebSocketNodeAbstract;
import org.zaproxy.zap.extension.websocket.treemap.nodes.structural.WebSocketNodeInterface;

public interface NodeFactory {

    /**
     * Adds WebSocket Message to the Tree Structure or updates the existing one.
     *
     * @param message is going to be inserted in the structure.
     * @return the {@link WebSocketNodeAbstract <WebSocketContent>} with the appropriate message
     *     content.
     */
    WebSocketNodeWrapper getMessageTreeNode(WebSocketMessageDTO message);

    WebSocketNodeInterface createMessageNode(
            WebSocketNodeInterface parent, int position, NodeContent nodeContent);

    /**
     * Adds the Host to the Tree Structure or just returns the existing one.
     *
     * @param channel is going to be inserted in the structure.
     * @return the {@link WebSocketNodeAbstract
     *     <org.zaproxy.zap.extension.websocket.treemap.nodes.contents.HostFolderContent>} either
     *     the created one or the existing one.
     * @throws DatabaseException if can't get Handshake {@link
     *     org.parosproxy.paros.network.HttpMessage} from the {@link
     *     org.parosproxy.paros.model.HistoryReference}.
     * @throws HttpMalformedHeaderException if the Handshake {@link
     *     org.parosproxy.paros.network.HttpMessage} is Malformed
     */
    WebSocketNodeWrapper getHostTreeNode(WebSocketChannelDTO channel)
            throws DatabaseException, HttpMalformedHeaderException;

    WebSocketNodeInterface createHostNode(
            WebSocketNodeInterface parent, int position, NodeContent nodeContent);

    /** @return the Root of Tree Structure */
    WebSocketNodeInterface getRoot();
}
