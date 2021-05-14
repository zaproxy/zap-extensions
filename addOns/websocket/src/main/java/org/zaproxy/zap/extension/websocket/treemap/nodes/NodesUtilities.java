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
package org.zaproxy.zap.extension.websocket.treemap.nodes;

import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.zaproxy.zap.extension.websocket.WebSocketChannelDTO;

public class NodesUtilities {

    /** Give handshakeMessage and channel returns the Hostname. */
    public static String getHostName(WebSocketChannelDTO channel)
            throws DatabaseException, HttpMalformedHeaderException {

        StringBuilder host = new StringBuilder();

        int port = getPort(channel);

        String scheme;
        if (port == 443
                || channel.getHandshakeReference().getHttpMessage().getRequestHeader().isSecure()) {
            scheme = "wss";
        } else {
            scheme = "ws";
        }
        host.append(scheme).append("://").append(channel.getHost());

        if ((port != 80 && port != 443)) {
            host.append(":").append(port);
        }

        return host.toString();
    }

    private static int getPort(WebSocketChannelDTO channel)
            throws DatabaseException, HttpMalformedHeaderException {
        return channel.getPort() != -1
                ? channel.getPort()
                : channel.getHandshakeReference()
                        .getHttpMessage()
                        .getRequestHeader()
                        .getURI()
                        .getPort();
    }
}
