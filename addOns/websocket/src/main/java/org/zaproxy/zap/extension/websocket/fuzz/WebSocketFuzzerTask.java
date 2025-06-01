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

import java.util.List;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.zap.extension.fuzz.AbstractFuzzerTask;
import org.zaproxy.zap.extension.websocket.WebSocketFuzzMessageDTO;
import org.zaproxy.zap.extension.websocket.WebSocketMessageDTO;
import org.zaproxy.zap.extension.websocket.WebSocketProxy;
import org.zaproxy.zap.extension.websocket.WebSocketProxy.Initiator;

public class WebSocketFuzzerTask extends AbstractFuzzerTask<WebSocketMessageDTO> {

    private static final Logger LOGGER = LogManager.getLogger(WebSocketFuzzerTask.class);

    public WebSocketFuzzerTask(
            long id, WebSocketFuzzer parent, WebSocketMessageDTO message, List<Object> payloads) {
        super(id, parent, message, payloads);
    }

    @Override
    protected WebSocketFuzzer getParent() {
        return (WebSocketFuzzer) super.getParent();
    }

    @Override
    protected void runImpl(WebSocketMessageDTO message, List<Object> payloads) {
        getParent().preProcessMessage(getId(), message, payloads);
        WebSocketFuzzMessageDTO messageSent =
                sendMessage(getParent().getWebSocketProxies(), (WebSocketFuzzMessageDTO) message);
        if (messageSent == null) {
            return;
        }
        getParent().messageSent(getId(), messageSent);

        WebSocketFuzzResult result = new WebSocketFuzzResult(getId(), messageSent, payloads);
        String fuzz = payloads.toString();
        messageSent.fuzz = fuzz.substring(0, Math.min(150, fuzz.length()));
        getParent().fuzzResultAvailable(result);
    }

    private WebSocketFuzzMessageDTO sendMessage(
            Map<Integer, WebSocketProxy> wsProxies, WebSocketFuzzMessageDTO message) {
        if (!wsProxies.containsKey(message.getChannel().getId())) {
            getParent().stopScan();
            return null;
        }

        try {
            WebSocketProxy wsProxy = wsProxies.get(message.getChannel().getId());

            message.fuzzId = getParent().getId();
            if (wsProxy.send(message, Initiator.FUZZER)) {
                message.state = WebSocketFuzzMessageDTO.State.SUCCESSFUL;
            } else {
                message.state = WebSocketFuzzMessageDTO.State.ERROR;
            }
            return message;
        } catch (Exception e) {
            LOGGER.warn("Failed to send WebSocket fuzzed message, cause: {}", e.getMessage());
        }
        return null;
    }
}
