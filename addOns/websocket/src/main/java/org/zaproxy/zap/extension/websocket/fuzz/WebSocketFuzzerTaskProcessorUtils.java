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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.zap.extension.websocket.WebSocketFuzzMessageDTO;
import org.zaproxy.zap.extension.websocket.WebSocketMessageDTO;
import org.zaproxy.zap.extension.websocket.WebSocketProxy;
import org.zaproxy.zap.extension.websocket.WebSocketProxy.Initiator;

public class WebSocketFuzzerTaskProcessorUtils {

    private static final Logger LOGGER =
            LogManager.getLogger(WebSocketFuzzerTaskProcessorUtils.class);

    private final WebSocketFuzzer websocketFuzzer;
    private final WebSocketMessageDTO originalMessage;
    private final long taskId;
    private final List<Object> payloads;
    private String processorName;

    protected WebSocketFuzzerTaskProcessorUtils(
            WebSocketFuzzer websocketFuzzer,
            WebSocketMessageDTO originalMessage,
            long taskId,
            List<Object> payloads) {
        this.websocketFuzzer = websocketFuzzer;
        this.originalMessage = originalMessage;
        this.taskId = taskId;
        this.payloads = payloads;
    }

    protected void setCurrentProcessorName(String name) {
        processorName = name;
    }

    public WebSocketMessageDTO getOriginalMessage() {
        return originalMessage;
    }

    public void stopFuzzer() {
        websocketFuzzer.stopScan();
    }

    public List<Object> getPayloads() {
        return payloads;
    }

    public void increaseErrorCount(String reason) {
        websocketFuzzer.increaseErrorCount(taskId, processorName, reason);
    }

    public boolean sendMessage(String message) {
        return sendMessage(message, true);
    }

    public boolean sendMessage(String message, boolean includeInResults) {
        WebSocketProxy wsProxy =
                websocketFuzzer.getWebSocketProxies().get(originalMessage.getChannel().getId());
        if (wsProxy == null) {
            websocketFuzzer.stopScan();
            return false;
        }

        try {

            WebSocketFuzzMessageDTO newMessage = new WebSocketFuzzMessageDTO();
            originalMessage.copyInto(newMessage);

            newMessage.fuzzId = websocketFuzzer.getId();
            newMessage.setPayload(message);
            newMessage.setPayloadLength(Integer.valueOf(message.length()));
            newMessage.fuzz = "";

            if (wsProxy.send(newMessage, Initiator.FUZZER)) {
                websocketFuzzer.messageSent(taskId, newMessage);
                newMessage.state = WebSocketFuzzMessageDTO.State.SUCCESSFUL;
            } else {
                newMessage.state = WebSocketFuzzMessageDTO.State.ERROR;
            }

            if (includeInResults) {
                websocketFuzzer.fuzzResultAvailable(
                        new WebSocketFuzzResult(taskId, newMessage, payloads));
            }
            return true;
        } catch (Exception e) {
            LOGGER.warn("Failed to send WebSocket message, cause: {}", e.getMessage());
        }
        return false;
    }
}
