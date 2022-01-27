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
package org.zaproxy.zap.extension.websocket;

import java.net.Socket;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.eventBus.Event;
import org.zaproxy.zap.eventBus.EventPublisher;
import org.zaproxy.zap.extension.websocket.WebSocketProxy.Initiator;
import org.zaproxy.zap.extension.websocket.WebSocketProxy.State;

/** A {@link EventPublisher} of websocket events. */
public final class WebSocketEventPublisher implements EventPublisher, WebSocketSenderListener {

    /** The event sent when a {@code WebSocketMessage} is seen. */
    public static final String EVENT_MESSAGE = "ws.message";
    /** The event sent when a {@code WebSocketProxy} state change occurs. */
    public static final String EVENT_STATE_CHANGE = "ws.stateChange";

    private static final String FIELD_STATE = "state";
    private static final String FIELD_CHANNEL_ID = "channelId";
    private static final String FIELD_CHANNEL_HOST = "channelHost";
    private static final String FIELD_LOCAL_SOCKET = "localSocket";
    private static final String FIELD_REMOTE_SOCKET = "remoteSocket";
    private static final String FIELD_TIME_IN_MS = "timeSentInMs";
    private static final String FIELD_OP_CODE = "opCode";
    private static final String FIELD_OP_CODE_STRING = "opCodeString";
    private static final String FIELD_DIRECTION = "direction";
    private static final String FIELD_LENGTH = "length";
    private static final String FIELD_MSG_ID = "messageId";
    private static final String FIELD_MSG_SUMMARY = "messageSummary";

    private ExtensionWebSocket extension;
    private ExecutorService executor;

    public WebSocketEventPublisher(ExtensionWebSocket extension) {
        this.extension = extension;
        executor =
                Executors.newSingleThreadExecutor(
                        r -> new Thread(r, "ZAP-WebSocketEventPublisher"));

        ZAP.getEventBus().registerPublisher(this, new String[] {EVENT_MESSAGE, EVENT_STATE_CHANGE});
    }

    @Override
    public String getPublisherName() {
        return WebSocketEventPublisher.class.getCanonicalName();
    }

    @Override
    public int getListenerOrder() {
        // We want this to run after most listeners
        return 100000;
    }

    @Override
    public void onMessageFrame(int channelId, WebSocketMessage message, Initiator initiator) {
        WebSocketProxy proxy = extension.getWebSocketProxy(channelId);
        if (proxy != null && proxy.isAllowAPI()) {
            // Sending an event on an API message will cause an infinite loop
            return;
        }
        if (message.isFinished) {
            this.executor.execute(
                    () -> {
                        Map<String, String> map = new HashMap<>();
                        map.put(FIELD_CHANNEL_ID, Integer.toString(channelId));
                        map.put(FIELD_CHANNEL_HOST, message.getDTO().getChannel().getHost());
                        map.put(FIELD_TIME_IN_MS, Long.toString(message.getTimestamp().getTime()));
                        map.put(FIELD_OP_CODE, Integer.toString(message.getOpcode()));
                        map.put(FIELD_OP_CODE_STRING, message.getOpcodeString());
                        map.put(FIELD_DIRECTION, message.getDirection().name());
                        map.put(FIELD_MSG_ID, Integer.toString(message.getMessageId()));
                        map.put(FIELD_LENGTH, Integer.toString(message.getPayloadLength()));
                        if (message.isText()) {
                            String txt = message.getReadablePayload();
                            if (txt.length() > 1024) {
                                txt = txt.substring(0, 1024);
                            }
                            map.put(FIELD_MSG_SUMMARY, txt);
                        } else {
                            // Generate a hex version so that its slightly more readable
                            StringBuilder sb = new StringBuilder();
                            for (byte b : message.getPayload()) {
                                sb.append(String.format("%02X ", b));
                                if (sb.length() > 1024) {
                                    break;
                                }
                            }
                            map.put(FIELD_MSG_SUMMARY, sb.toString());
                        }
                        ZAP.getEventBus()
                                .publishSyncEvent(this, new Event(this, EVENT_MESSAGE, null, map));
                    });
        }
    }

    private String socketToStr(Socket socket) {
        if (socket == null) {
            return "";
        }
        return socket.getLocalAddress().toString() + ":" + socket.getPort();
    }

    @Override
    public void onStateChange(State state, WebSocketProxy proxy) {
        this.executor.execute(
                () -> {
                    Map<String, String> map = new HashMap<>();
                    map.put(FIELD_STATE, state.name());
                    map.put(FIELD_CHANNEL_ID, Integer.toString(proxy.getChannelId()));
                    map.put(FIELD_LOCAL_SOCKET, socketToStr(proxy.localSocket));
                    map.put(FIELD_REMOTE_SOCKET, socketToStr(proxy.remoteSocket));
                    ZAP.getEventBus()
                            .publishSyncEvent(this, new Event(this, EVENT_STATE_CHANGE, null, map));
                });
    }

    public void shutdown() {
        ZAP.getEventBus().unregisterPublisher(this);
        this.executor.shutdown();
    }
}
