/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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
package org.zaproxy.zap.testutils.websocket.server;

import fi.iki.elonen.NanoHTTPD;
import fi.iki.elonen.NanoWSD;
import fi.iki.elonen.NanoWSD.WebSocketFrame;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Stack;
import java.util.Timer;
import java.util.TimerTask;

/** Represent a WebSocket Test connection. */
public class NanoWebSocketConnection extends NanoWSD.WebSocket {

    private static final String CLOSE_PAYLOAD = "Connection Closed";
    private static final String CLOSE_FROM_PING = "No ping response";
    private byte[] pingPayload;
    private Scheduling scheduling;
    private boolean pongReceived = true;
    private Stack<WebSocketFrame> incomingMessages;
    private Stack<WebSocketFrame> outgoingMessages;
    private WebSocketFrameListener incomingListener;

    public NanoWebSocketConnection(NanoHTTPD.IHTTPSession handshakeRequest) {
        super(handshakeRequest);
        incomingMessages = new Stack<>();
        outgoingMessages = new Stack<>();
    }

    /**
     * Set up a ping Schedule.
     *
     * @param pingInterval how often in milliseconds send ping message.
     * @param pingPayload the ping message.
     */
    public void setPingScheduling(int pingInterval, byte[] pingPayload) {
        scheduling = new Scheduling();
        this.pingPayload = pingPayload;
        scheduling.pingScheduling(pingInterval);
    }

    protected synchronized boolean isPongReceived() {
        return pongReceived;
    }

    protected synchronized void setPongReceived(boolean pongReceived) {
        this.pongReceived = pongReceived;
    }

    /**
     * Sends a ping message to the client. Ping payload defined by {@link
     * NanoWebSocketConnection#setPingMessage(byte[])}
     */
    protected synchronized boolean ping() {
        try {
            if (isPongReceived()) {
                super.ping(pingPayload);
                setPongReceived(false);
            } else {
                onClose(WebSocketFrame.CloseCode.AbnormalClosure, CLOSE_FROM_PING, false);
            }
        } catch (IOException e) {
            e.printStackTrace();
            onClose(WebSocketFrame.CloseCode.AbnormalClosure, CLOSE_PAYLOAD, false);
            return false;
        }
        return true;
    }

    @Override
    protected void onOpen() {}

    @Override
    protected void onClose(WebSocketFrame.CloseCode closeCode, String s, boolean b) {}

    @Override
    protected void onMessage(WebSocketFrame webSocketFrame) {
        receivedFrame(webSocketFrame);
    }

    private void receivedFrame(WebSocketFrame webSocketFrame) {
        if (incomingListener != null) {
            incomingListener.frameReceived(webSocketFrame);
        }
        incomingMessages.push(webSocketFrame);
    }

    @Override
    protected void onPong(WebSocketFrame webSocketFrame) {
        receivedFrame(webSocketFrame);
        setPongReceived(true);
    }

    @Override
    protected void onException(IOException e) {}

    public void setPingMessage(byte[] payload) {
        this.pingPayload = payload;
    }

    public WebSocketFrame popIncomingMessage() {
        return incomingMessages.pop();
    }

    /**
     * Creates a schedule in order to send messages.
     *
     * @param messages Stack of the messages is going to be sent
     * @param messageInterval the interval of the messages
     */
    public void setOutgoingMessageSchedule(Stack<WebSocketFrame> messages, int messageInterval) {
        if (scheduling == null) {
            scheduling = new Scheduling();
        }
        outgoingMessages = messages;
        scheduling.messageScheduling(messageInterval);
    }

    public List<WebSocketFrame> getListOfIncomingMessages() {
        return new ArrayList<WebSocketFrame>(incomingMessages);
    }

    class Scheduling {
        protected Timer pingTimer;
        protected Timer messageTimer;

        public Scheduling() {
            super();
        }

        void pingScheduling(int pingInterval) {
            pingTimer = new Timer("pingTimer");
            pingTimer.scheduleAtFixedRate(new SendPing(), pingInterval, pingInterval);
        }

        void messageScheduling(int messageInterval) {
            messageTimer = new Timer("messageTimer");
            messageTimer.scheduleAtFixedRate(new SendMessage(), messageInterval, messageInterval);
        }

        class SendPing extends TimerTask {
            @Override
            public void run() {
                if (!ping()) {
                    pingTimer.cancel();
                }
            }
        }

        class SendMessage extends TimerTask {
            @Override
            public void run() {
                synchronized (outgoingMessages) {
                    try {
                        if (!outgoingMessages.empty()) {
                            sendFrame(outgoingMessages.pop());
                        } else {
                            messageTimer.cancel();
                        }
                    } catch (IOException e) {
                        messageTimer.cancel();
                        e.printStackTrace();
                    }
                }
            }
        }
    }

    public void addIncomingWebSocketFrameListener(WebSocketFrameListener listener) {
        this.incomingListener = listener;
    }

    public interface WebSocketFrameListener {

        void frameReceived(WebSocketFrame frame);
    }
}
