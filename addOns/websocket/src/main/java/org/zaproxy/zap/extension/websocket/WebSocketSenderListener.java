/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2017 The ZAP Development Team
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

import org.zaproxy.zap.extension.websocket.WebSocketProxy.Initiator;
import org.zaproxy.zap.extension.websocket.WebSocketProxy.State;

/**
 * Provides a callback mechanism to get notified of WebSocket messages. The differences between
 * {@link WebSocketSenderListener} and {@link WebSocketObserver} are below.
 *
 * <p>- {@link WebSocketSenderListener} receives all state change/frame notifies from {@link
 * WebSocketProxy}.
 *
 * <p>- {@link WebSocketObserver} receives state change/frame notifies when {@link
 * WebSocketProxy#isForwardOnly} is true.
 *
 * <p>- {@link WebSocketObserver#onMessageFrame(int, WebSocketMessage)} doesn't receive notifies
 * which sent from WebSocket Fuzzer.
 *
 * <p>- {@link WebSocketObserver#onMessageFrame(int, WebSocketMessage)} can control message
 * forwarding, but {@link WebSocketSenderListener#onMessageFrame(int, WebSocketMessage, int)} can
 * not.
 *
 * <p>In other words, {@link WebSocketObserver} is similar to {@link ProxyListener} and {@link
 * WebSocketSenderListener} is similar to {@link HttpSenderListener}.
 *
 * <p>You can add your listener to a specific channel via {@link
 * WebSocketProxy#addSenderListener(WebSocketSenderListener)}. Alternatively you can set up your
 * listener for all channels, that come into existence in the future. Call {@link
 * ExtensionWebSocket#addAllChannelSenderListener(WebSocketSenderListener)}.
 */
public interface WebSocketSenderListener {
    /**
     * Gets the order of when this listener should be notified.
     *
     * <p>The listeners are ordered in a natural order, the greater the order the later it will be
     * notified.
     *
     * <p><strong>Note:</strong> If two or more listeners have the same order, the order that those
     * listeners will be notified is undefined.
     *
     * @return an {@code int} with the value of the order that this listener should be notified
     *     about
     */
    int getListenerOrder();

    /**
     * Called by the proxied class ({@link WebSocketProxy}) when a new part of a message arrives.
     *
     * <p>Use {@link WebSocketMessage#isFinished()} to determine if it is ready to process. If false
     * is returned, the given message part will not be further processed (i.e. forwarded).
     *
     * @param channelId
     * @param message contains message parts received so far
     * @param initiator
     */
    void onMessageFrame(int channelId, WebSocketMessage message, Initiator initiator);

    /**
     * Called by the proxied class ({@link WebSocketProxy}) when its internal {@link
     * WebSocketProxy#state} changes.
     *
     * <p>This state does not only represent all possible WebSocket connection states, but also
     * state changes that affect how messages are processed.
     *
     * @param state new state
     * @param proxy
     */
    void onStateChange(State state, WebSocketProxy proxy);
}
