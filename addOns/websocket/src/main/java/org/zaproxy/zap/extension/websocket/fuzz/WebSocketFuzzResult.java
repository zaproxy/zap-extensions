/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2015 The ZAP Development Team
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
package org.zaproxy.zap.extension.websocket.fuzz;

import java.util.Collections;
import java.util.List;
import org.zaproxy.zap.extension.websocket.WebSocketFuzzMessageDTO;

public class WebSocketFuzzResult {

    private final long taskId;

    private final WebSocketFuzzMessageDTO message;
    private final List<Object> payloads;

    public WebSocketFuzzResult(long taskId, WebSocketFuzzMessageDTO message) {
        this(taskId, message, Collections.emptyList());
    }

    public WebSocketFuzzResult(
            long taskId, WebSocketFuzzMessageDTO message, List<Object> payloads) {
        this.taskId = taskId;
        this.message = message;
        this.payloads = payloads;
    }

    public long getTaskId() {
        return taskId;
    }

    public List<Object> getPayloads() {
        return payloads;
    }

    public WebSocketFuzzMessageDTO getWebSocketMessage() {
        return message;
    }
}
