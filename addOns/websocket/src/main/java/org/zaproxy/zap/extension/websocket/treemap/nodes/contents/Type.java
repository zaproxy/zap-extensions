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

import static org.zaproxy.zap.extension.websocket.WebSocketMessage.OPCODE_CLOSE;
import static org.zaproxy.zap.extension.websocket.WebSocketMessage.OPCODE_PING;

import org.zaproxy.zap.extension.websocket.WebSocketMessage;

public enum Type {
    MESSAGES(1),
    HEARTBEAT(2),
    CLOSE(3);

    int order;

    Type(int order) {
        this.order = order;
    }

    public int getOrder() {
        return order;
    }

    public static Type getType(Integer opcode) {
        switch (opcode) {
            case OPCODE_CLOSE:
                return CLOSE;
            case OPCODE_PING:
            case WebSocketMessage.OPCODE_PONG:
                return HEARTBEAT;
            default:
                return MESSAGES;
        }
    }
}
