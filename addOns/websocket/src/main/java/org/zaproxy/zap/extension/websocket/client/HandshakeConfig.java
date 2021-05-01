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
package org.zaproxy.zap.extension.websocket.client;

import java.util.ArrayList;
import java.util.List;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.websocket.WebSocketObserver;
import org.zaproxy.zap.extension.websocket.WebSocketSenderListener;

/**
 * This class wrap up the HttpMessage and the appropriate options were necessary for handshake
 * request
 */
public class HandshakeConfig {

    private HttpMessage httpMessage;
    private boolean followRedirects;
    private boolean useSessionState;
    private List<WebSocketObserver> websocketObservers;
    private List<WebSocketSenderListener> webSocketSenderListeners;

    /**
     * Creates a basic configuration for a handshake message
     *
     * @param httpMessage the http handshake message
     * @param followRedirects {@code true} to follow redirection
     * @param useSessionState {@code true} in order to send a state http request
     */
    public HandshakeConfig(
            HttpMessage httpMessage, boolean followRedirects, boolean useSessionState) {
        this.httpMessage = httpMessage;
        this.followRedirects = followRedirects;
        this.useSessionState = useSessionState;
    }

    /**
     * Creates a basic configuration for a handshake message
     *
     * @param httpMessage the http handshake message
     */
    public HandshakeConfig(HttpMessage httpMessage) {
        this.httpMessage = httpMessage;
    }

    public HttpMessage getHttpMessage() {
        return httpMessage;
    }

    public void setHttpMessage(HttpMessage httpMessage) {
        this.httpMessage = httpMessage;
    }

    public boolean isFollowRedirects() {
        return followRedirects;
    }

    public void setFollowRedirects(boolean followRedirects) {
        this.followRedirects = followRedirects;
    }

    public boolean isUseSessionState() {
        return useSessionState;
    }

    public void setUseSessionState(boolean useSessionState) {
        this.useSessionState = useSessionState;
    }

    /** Add an observer that is attached to the new channel connection in future. */
    public void addChannelObserver(WebSocketObserver observer) {
        if (websocketObservers == null) {
            websocketObservers = new ArrayList<>();
        }
        websocketObservers.add(observer);
    }

    /**
     * Removes the given {@code observer}, that will be attached to channel.
     *
     * @param observer the observer to be removed
     * @throws IllegalArgumentException if the given {@code observer} is {@code null}.
     */
    public void removeChannelObserver(WebSocketObserver observer) {
        if (observer == null) {
            throw new IllegalArgumentException("The parameter observer must not be null.");
        }
        if (websocketObservers != null) {
            websocketObservers.remove(observer);
        }
    }

    /** Add an sender listener that is attached to the new channel connection in future. */
    public void addChannelSenderListener(WebSocketSenderListener senderListener) {
        if (webSocketSenderListeners == null) {
            webSocketSenderListeners = new ArrayList<>();
        }
        webSocketSenderListeners.add(senderListener);
    }

    /**
     * Removes the given {@code senderListener}, that will be attached to channel.
     *
     * @param senderListener the sender listener to be removed
     * @throws IllegalArgumentException if the given {@code senderListener} is {@code null}.
     */
    public void removeChannelSenderListener(WebSocketSenderListener senderListener) {
        if (senderListener == null) {
            throw new IllegalArgumentException("The parameter senderListener must not be null.");
        }
        if (webSocketSenderListeners != null) {
            webSocketSenderListeners.remove(senderListener);
        }
    }

    public List<WebSocketObserver> getWebsocketObservers() {
        return websocketObservers;
    }

    public List<WebSocketSenderListener> getWebSocketSenderListeners() {
        return webSocketSenderListeners;
    }
}
