/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2012 The ZAP Development Team
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
package org.zaproxy.zap.extension.websocket.manualsend;

import java.awt.EventQueue;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.extension.manualrequest.MessageSender;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.httppanel.Message;
import org.zaproxy.zap.extension.websocket.WebSocketMessage;
import org.zaproxy.zap.extension.websocket.WebSocketMessageDTO;
import org.zaproxy.zap.extension.websocket.WebSocketObserver;
import org.zaproxy.zap.extension.websocket.WebSocketProxy;
import org.zaproxy.zap.extension.websocket.WebSocketProxy.Initiator;
import org.zaproxy.zap.extension.websocket.WebSocketProxy.State;
import org.zaproxy.zap.extension.websocket.client.HandshakeConfig;
import org.zaproxy.zap.extension.websocket.client.HttpHandshakeBuilder;
import org.zaproxy.zap.extension.websocket.client.RequestOutOfScopeException;
import org.zaproxy.zap.extension.websocket.ui.WebSocketPanel;
import org.zaproxy.zap.model.SessionStructure;

/** Knows how to send {@link HttpMessage} objects. Contains a list of valid WebSocket channels. */
public class WebSocketPanelSender implements MessageSender, WebSocketObserver {

    private static final Logger logger = Logger.getLogger(WebSocketPanelSender.class);

    private Map<Integer, WebSocketProxy> connectedProxies;
    private Map<Integer, WebSocketProxy> closedProxies;
    private ExtensionHistory historyExtension = null;

    public WebSocketPanelSender() {
        connectedProxies = new HashMap<>();
        closedProxies = new HashMap<>();
    }

    @Override
    public void handleSendMessage(Message aMessage) throws IOException {
        final WebSocketMessageDTO websocketMessage = (WebSocketMessageDTO) aMessage;

        if (websocketMessage.channel == null || websocketMessage.channel.id == null) {
            logger.warn(
                    "Invalid WebSocket channel selected. Unable to send manual crafted message!");
            throw new IllegalArgumentException(
                    Constant.messages.getString("websocket.manual_send.fail.invalid_channel")
                            + " "
                            + Constant.messages.getString("websocket.manual_send.fail"));
        }

        if (websocketMessage.opcode == null) {
            logger.warn(
                    "Invalid WebSocket opcode selected. Unable to send manual crafted message!");
            throw new IllegalArgumentException(
                    Constant.messages.getString("websocket.manual_send.fail.invalid_opcode")
                            + " "
                            + Constant.messages.getString("websocket.manual_send.fail"));
        }

        WebSocketProxy wsProxy = getDelegate(websocketMessage.channel.id);
        if (!websocketMessage.isOutgoing && wsProxy.isClientMode()) {
            logger.warn(
                    "Invalid WebSocket direction 'incoming' selected for Proxy in Client Mode. Unable to send manual crafted message!");
            throw new IllegalArgumentException(
                    Constant.messages.getString(
                                    "websocket.manual_send.fail.invalid_direction_client_mode")
                            + " "
                            + Constant.messages.getString("websocket.manual_send.fail"));
        }
        wsProxy.sendAndNotify(websocketMessage, Initiator.MANUAL_REQUEST);
    }

    @Override
    public void cleanup() {}

    private WebSocketProxy getDelegate(Integer channelId) {
        if (closedProxies.containsKey(channelId)) {
            logger.warn(
                    "Selected WebSocket channel is not connected. Unable to send manual crafted message!");
            throw new IllegalArgumentException(
                    Constant.messages.getString("websocket.manual_send.fail.disconnected_channel")
                            + " "
                            + Constant.messages.getString("websocket.manual_send.use_reopen"));
        }
        return connectedProxies.get(channelId);
    }

    /**
     * Re-establish the connection
     *
     * @param channelId channel to re-open
     * @param followRedirects true to follow redirection
     * @param useSessionState false for stateless http request
     * @throws IOException if an I/O error occurred
     * @throws RequestOutOfScopeException if url it's out of scope ore or ZAP runs to safe or
     *     protected mode
     * @throws IllegalStateException if an error occurred while trying to retrieve the HTTP
     *     handshake from history
     * @return the new channel id
     */
    public int reOpenChannel(
            Integer channelId,
            String newSecWebSocketKey,
            boolean followRedirects,
            boolean useSessionState)
            throws RequestOutOfScopeException, IOException {
        WebSocketProxy connectionToEstablish = getWebSocketProxy(channelId);
        HandshakeConfig handshakeConfig;

        handshakeConfig = connectionToEstablish.getHandShakeConfig();
        handshakeConfig.setFollowRedirects(followRedirects);
        handshakeConfig.setUseSessionState(useSessionState);

        if (newSecWebSocketKey != null) {
            HttpHandshakeBuilder.setWebSocketKey(
                    handshakeConfig.getHttpMessage().getRequestHeader(), newSecWebSocketKey);
        } else {
            HttpHandshakeBuilder.setGeneratedWebSocketKey(
                    handshakeConfig.getHttpMessage().getRequestHeader());
        }

        WebSocketProxy newWebSocketConnection =
                connectionToEstablish.reEstablishConnection(handshakeConfig);

        addHistoryReference(handshakeConfig.getHttpMessage(), newWebSocketConnection);

        return newWebSocketConnection != null ? newWebSocketConnection.getChannelId() : -1;
        // (-1) should not be happened, if something went wrong should throw exception
    }

    /**
     * Return the Sec-WebSocket-Key of a specific channel
     *
     * @param channelId the channel
     * @return the Sec-WebSocket-Key
     * @throws DatabaseException unable to get the {@link HttpMessage} from {@link HistoryReference}
     * @throws HttpMalformedHeaderException malformed Http message (should not be happened)
     */
    public String getWebSocketKey(Integer channelId)
            throws DatabaseException, HttpMalformedHeaderException {
        return getWebSocketProxy(channelId)
                .getHandshakeReference()
                .getHttpMessage()
                .getRequestHeader()
                .getHeader(HttpHandshakeBuilder.SEC_WEB_SOCKET_KEY);
    }

    private WebSocketProxy getWebSocketProxy(Integer channelId) {
        if (closedProxies.containsKey(channelId)) {
            return closedProxies.get(channelId);
        } else if (connectedProxies.containsKey(channelId)) {
            return connectedProxies.get(channelId);
        } else {
            throw new IllegalArgumentException(
                    Constant.messages.getString("websocket.manual_send.fail.invalid_channel"));
        }
    }

    private void addHistoryReference(HttpMessage httpMessage, WebSocketProxy webSocketProxy) {
        if (!EventQueue.isDispatchThread()) {
            EventQueue.invokeLater(() -> addHistoryReference(httpMessage, webSocketProxy));
            return;
        }

        try {

            Session session = Model.getSingleton().getSession();
            HistoryReference ref =
                    new HistoryReference(session, HistoryReference.TYPE_ZAP_USER, httpMessage);
            webSocketProxy.setHandshakeReference(ref);

            final ExtensionHistory extHistory = getHistoryExtension();
            if (extHistory != null) {
                extHistory.addHistory(ref);
            }

            SessionStructure.addPath(Model.getSingleton(), ref, httpMessage);

        } catch (HttpMalformedHeaderException | DatabaseException e) {
            logger.warn("Failed to persist message sent:", e);
        }
    }

    private ExtensionHistory getHistoryExtension() {
        if (historyExtension == null) {
            historyExtension =
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionHistory.class);
        }
        return historyExtension;
    }

    @Override
    public int getObservingOrder() {
        return WebSocketPanel.WEBSOCKET_OBSERVING_ORDER + 1;
    }

    @Override
    public boolean onMessageFrame(int channelId, WebSocketMessage message) {
        return true;
    }

    @Override
    public void onStateChange(State state, WebSocketProxy proxy) {
        if (state.equals(WebSocketProxy.State.OPEN)) {
            connectedProxies.put(proxy.getChannelId(), proxy);
        } else if (state.equals(WebSocketProxy.State.CLOSING)) {
            connectedProxies.remove(proxy.getChannelId());
            closedProxies.put(proxy.getChannelId(), proxy);
        }
    }
}
