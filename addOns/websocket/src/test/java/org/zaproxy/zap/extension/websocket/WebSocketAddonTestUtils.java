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

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.zap.extension.websocket.client.HandshakeConfig;
import org.zaproxy.zap.extension.websocket.client.HttpHandshakeBuilder;
import org.zaproxy.zap.extension.websocket.client.ServerConnectionEstablisher;
import org.zaproxy.zap.testutils.WebSocketTestUtils;

public abstract class WebSocketAddonTestUtils extends WebSocketTestUtils {

    public WebSocketProxy setupWebSocketProxy() {
        ServerConnectionEstablisher establisher = new ServerConnectionEstablisher();
        try {
            HttpMessage handshakeRequest =
                    new HttpMessage(
                            HttpHandshakeBuilder.getHttpHandshakeRequestHeader(
                                    super.getServerUrl()));
            return establisher.send(new HandshakeConfig(handshakeRequest, false, false));
        } catch (Exception e) {
            return null;
        }
    }

    public WebSocketMessageDTO sendOutgoingMessage(WebSocketProxy webSocketProxy, String message) {
        WebSocketMessageDTO webSocketMessage = new WebSocketMessageDTO(webSocketProxy.getDTO());
        webSocketMessage.setPayload(message);
        webSocketMessage.setOpcode(WebSocketMessage.OPCODE_TEXT);
        webSocketMessage.setOutgoing(true);

        try {
            return webSocketProxy.send(webSocketMessage, WebSocketProxy.Initiator.MANUAL_REQUEST)
                    ? webSocketMessage
                    : null;
        } catch (IOException e) {
            return null;
        }
    }

    public HistoryReference getMockHistoryReference(URI serverUrl)
            throws HttpMalformedHeaderException, DatabaseException {

        HttpRequestHeader handshakeRequest =
                HttpHandshakeBuilder.getHttpHandshakeRequestHeader(serverUrl);
        HttpMessage handshakeMessage = new HttpMessage(handshakeRequest);

        HistoryReference historyReference = mock(HistoryReference.class);
        when(historyReference.getURI()).thenReturn(serverUrl);
        when(historyReference.getHttpMessage()).thenReturn(handshakeMessage);
        return historyReference;
    }

    public HistoryReference getMockHistoryReference(String hostName, boolean isEscaped)
            throws HttpMalformedHeaderException, DatabaseException, URIException {
        return getMockHistoryReference(new URI(hostName, isEscaped));
    }

    public WebSocketProxy getMockWebSocketProxy(
            HistoryReference handshakeRef, WebSocketChannelDTO channel) {
        WebSocketProxy proxy = mock(WebSocketProxy.class);
        when(proxy.getDTO()).thenReturn(channel);
        when(proxy.getHandshakeReference()).thenReturn(handshakeRef);
        when(proxy.getChannelId()).thenReturn(channel.getId());
        return proxy;
    }

    public WebSocketChannelDTO getWebSocketChannelDTO(int id, String hostName, String url) {
        WebSocketChannelDTO channel = new WebSocketChannelDTO(hostName);
        channel.setId(id);
        channel.setPort(443);
        channel.setUrl(url);
        return channel;
    }

    public WebSocketChannelDTO getWebSocketChannelDTO(int id, String hostName) {
        return getWebSocketChannelDTO(id, hostName, hostName);
    }

    public WebSocketMessageDTO getWebSocketMessageDTO(
            WebSocketChannelDTO channel,
            Integer opcode,
            boolean isOutgoing,
            Object payload,
            int id) {
        WebSocketMessageDTO message = new WebSocketMessageDTO(channel);
        message.setOutgoing(isOutgoing);
        message.setOpcode(opcode);
        message.setId(id);
        message.setPayload(payload);
        if (payload instanceof String) {
            message.setPayloadLength(((String) payload).length() * 4);
        }
        return message;
    }

    public WebSocketMessageDTO getTextOutgoingMessage(
            WebSocketChannelDTO channel, String payload, int id) {

        return getWebSocketMessageDTO(channel, WebSocketMessage.OPCODE_TEXT, true, payload, id);
    }

    public WebSocketMessageDTO getTextOutgoingMessage(String payload) {
        return getTextOutgoingMessage(getWebSocketChannelDTO(1, "hostname"), payload, 1);
    }

    protected static List<WebSocketMessageDTO> messages(WebSocketMessageDTO... messages) {
        if (messages == null || messages.length == 0) {
            return Collections.emptyList();
        }
        return Arrays.asList(messages);
    }

    protected static List<WebSocketChannelDTO> channels(WebSocketChannelDTO... channels) {
        if (channels == null || channels.length == 0) {
            return Collections.emptyList();
        }
        return Arrays.asList(channels);
    }
}
