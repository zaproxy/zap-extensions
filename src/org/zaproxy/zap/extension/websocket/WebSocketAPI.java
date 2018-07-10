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
package org.zaproxy.zap.extension.websocket;

import java.io.IOException;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import org.apache.commons.codec.binary.Hex;
import org.apache.log4j.Logger;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.eventBus.Event;
import org.zaproxy.zap.eventBus.EventConsumer;
import org.zaproxy.zap.extension.api.API;
import org.zaproxy.zap.extension.api.API.Format;
import org.zaproxy.zap.extension.api.API.RequestType;
import org.zaproxy.zap.extension.api.ApiAction;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.extension.api.ApiImplementor;
import org.zaproxy.zap.extension.api.ApiResponse;
import org.zaproxy.zap.extension.api.ApiResponseElement;
import org.zaproxy.zap.extension.api.ApiResponseList;
import org.zaproxy.zap.extension.api.ApiResponseSet;
import org.zaproxy.zap.extension.api.ApiView;
import org.zaproxy.zap.extension.websocket.WebSocketProxy.Initiator;
import org.zaproxy.zap.extension.websocket.WebSocketProxy.State;
import org.zaproxy.zap.extension.websocket.ui.WebSocketMessagesPayloadFilter;
import org.zaproxy.zap.extension.websocket.utility.InvalidUtf8Exception;
import org.zaproxy.zap.extension.websocket.utility.WebSocketUtils;
import org.zaproxy.zap.model.StructuralNode;
import org.zaproxy.zap.model.Target;
import org.zaproxy.zap.utils.ApiUtils;

import net.sf.json.JSONArray;
import net.sf.json.JSONException;
import net.sf.json.JSONObject;
import net.sf.json.JSONSerializer;

public class WebSocketAPI extends ApiImplementor {

    private static final String PREFIX = "websocket";

    private ExtensionWebSocket extension;

    private static final String VIEW_CHANNELS = "channels";
    private static final String VIEW_MESSAGE = "message";
    private static final String VIEW_MESSAGES = "messages";

    private static final String ACTION_SEND_TEXT_MESSAGE = "sendTextMessage";

    private static final String PARAM_COUNT = "count";
    private static final String PARAM_START = "start";
    private static final String PARAM_PAYLOAD_PREVIEW_LENGTH = "payloadPreviewLength";
    private static final String PARAM_CHANNEL_ID = "channelId";
    private static final String PARAM_MESSAGE_ID = "messageId";
    private static final String PARAM_OUTGOING = "outgoing";
    private static final String PARAM_MESSAGE = "message";

    private static final Logger LOG = Logger.getLogger(WebSocketAPI.class);

    private WebSocketObserver observer;

    private String callbackUrl;

    public WebSocketAPI(ExtensionWebSocket extension) {
        this.extension = extension;

        this.addApiView(new ApiView(VIEW_CHANNELS));
        this.addApiView(new ApiView(VIEW_MESSAGE, new String[] { PARAM_CHANNEL_ID, PARAM_MESSAGE_ID }));
        this.addApiView(
                new ApiView(
                        VIEW_MESSAGES,
                        null,
                        new String[] { PARAM_CHANNEL_ID, PARAM_START, PARAM_COUNT, PARAM_PAYLOAD_PREVIEW_LENGTH }));

        this.addApiAction(
                new ApiAction(ACTION_SEND_TEXT_MESSAGE, new String[] { PARAM_CHANNEL_ID, PARAM_OUTGOING, PARAM_MESSAGE }));

        callbackUrl = API.getInstance().getCallBackUrl(this, "https://" + API.API_DOMAIN);

    }

    public String getCallbackUrl(boolean wss) {
        if (wss) {
            return this.callbackUrl.replace("https://", "wss://");
        } else {
            return this.callbackUrl;
        }
    }

    @Override
    public String getPrefix() {
        return PREFIX;
    }

    @Override
    public String handleCallBack(HttpMessage msg) throws ApiException {
        try {
            if (LOG.isDebugEnabled()) {
                LOG.debug("callback url = " + msg.getRequestHeader().getURI());
            }

            String connectionHeader = msg.getRequestHeader().getHeader(HttpHeader.CONNECTION);
            String upgradeHeader = msg.getRequestHeader().getHeader("upgrade");

            if (connectionHeader != null && connectionHeader.toLowerCase().contains("upgrade")) {
                if (upgradeHeader != null && upgradeHeader.equalsIgnoreCase("websocket")) {
                    // Respond to handshake
                    // We are not performing any additional checks as we are assuming that any client that knows
                    // the randomly generated callback URL is trusted.
                    msg.setResponseHeader(API.getDefaultResponseHeader("101 Switching Protocols", null, 0));
                    msg.getResponseHeader().setHeader(HttpHeader.CONTENT_TYPE, null);
                    msg.getResponseHeader().setHeader(HttpHeader.CONNECTION, "Upgrade");
                    msg.getResponseHeader().setHeader("Upgrade", "websocket");

                    String secWebSocketKey = msg.getRequestHeader().getHeader("Sec-WebSocket-Key");
                    msg.getResponseHeader()
                            .setHeader("Sec-WebSocket-Accept", WebSocketUtils.encodeWebSocketKey(secWebSocketKey));
                }
            }
            return "";
        } catch (Exception e) {
            throw new ApiException(ApiException.Type.URL_NOT_FOUND, msg.getRequestHeader().getURI().toString());
        }
    }

    protected WebSocketObserver getWebSocketObserver() {
        if (observer == null) {
            observer = new WebSocketObserver() {

                @Override
                public int getObservingOrder() {
                    return 0;
                }

                @Override
                public boolean onMessageFrame(int channelId, WebSocketMessage message) {
                    WebSocketProxy proxy = extension.getWebSocketProxy(channelId);
                    if (proxy == null || ! proxy.isAllowAPI()) {
                        // Shouldnt happen, but just to be safe
                        return true;
                    }
                    try {
                        if (WebSocketMessage.isControl(message.opcode)) {
                            return false;
                        }
                        JSONObject json = JSONObject.fromObject(message.getReadablePayload());
                        String component = json.getString("component");
                        String name = json.getString("name");
                        JSONObject params = null;
                        if (json.has("params")) {
                            params = json.getJSONObject("params");
                        }
                        String response = null;

                        if ("event".equals(component)) {
                            // Special case
                            String type = json.getString("type");
                            if ("register".equals(type)) {
                                WebsocketEventConsumer ev = getEventConsumer(channelId);
                                ev.addPublisherName(name);
                                ZAP.getEventBus().registerConsumer(ev, name);
                            } else if ("unregister".equals(type)) {
                                WebsocketEventConsumer ev = getEventConsumer(channelId);
                                ev.removePublisherName(name);
                                ZAP.getEventBus().unregisterConsumer(ev, name);
                            } else {
                                throw new ApiException(ApiException.Type.BAD_TYPE, type);
                            }
                        } else {
                            ApiImplementor impl = API.getInstance().getImplementors().get(component);
                            RequestType reqType = RequestType.valueOf(json.getString("type"));
                            ApiResponse apiResp;

                            switch (reqType) {
                            case action:
                                apiResp = impl.handleApiAction(name, params);
                                response = apiResp.toJSON().toString();
                                break;
                            case view:
                                apiResp = impl.handleApiView(name, params);
                                response = apiResp.toJSON().toString();
                                break;
                            case other:
                            case pconn:
                                // Not currently supported
                                throw new ApiException(ApiException.Type.BAD_TYPE, reqType.name());
                            }
                        }
                        if (response != null) {
                            sendWebSocketMessage(proxy, response);
                        }
                    } catch (JSONException e) {
                        LOG.warn(e.getMessage(), e);
                        try {
                            ApiException e2 = new ApiException(ApiException.Type.ILLEGAL_PARAMETER, e.getMessage());
                            sendWebSocketMessage(proxy, e2.toString(Format.JSON, false));
                        } catch (IOException e1) {
                            LOG.error(e.getMessage(), e);
                        }
                    } catch (ApiException e) {
                        try {
                            sendWebSocketMessage(proxy, e.toString(Format.JSON, false));
                        } catch (IOException e1) {
                            LOG.error(e.getMessage(), e);
                        }
                    } catch (Exception e) {
                        LOG.error(e.getMessage(), e);
                    }
                    return false;
                }

                @Override
                public void onStateChange(State state, WebSocketProxy proxy) {
                    if (state != State.CLOSED) {
                        return;
                    }

                    removeEventConsumer(evMap.remove(proxy.getChannelId()));
                }
            };

        }
        return observer;
    }

    private void removeEventConsumer(WebsocketEventConsumer consumer) {
        if (consumer == null) {
            return;
        }

        // TODO replace the loop with:
        // ZAP.getEventBus().unregisterConsumer(consumer);
        // once available in targeted ZAP version.
        for (String publisherName : consumer.getPublisherNames()) {
            ZAP.getEventBus().unregisterConsumer(consumer, publisherName);
        }
    }

    private boolean sendWebSocketMessage(int channelId, boolean outgoing, String message) throws IOException {
        WebSocketProxy proxy = extension.getWebSocketProxy(channelId);
        if (proxy != null) {
            return sendWebSocketMessage(proxy, outgoing, message);
        }
        return false;
    }

    private boolean sendWebSocketMessage(WebSocketProxy proxy, String message) throws IOException {
        return this.sendWebSocketMessage(proxy, false, message);
    }

    private boolean sendWebSocketMessage(WebSocketProxy proxy, boolean outgoing, String message) throws IOException {
        WebSocketMessageDTO resp = new WebSocketMessageDTO();
        resp.channel = proxy.getDTO();
        resp.payload = message;
        resp.payloadLength = message.length();
        resp.opcode = WebSocketMessage.OPCODE_TEXT;
        resp.isOutgoing = outgoing;
        boolean sent = proxy.send(resp, Initiator.WEB_SOCKET);
        if (sent) {
            try {
                extension.recordMessage(resp);
            } catch (DatabaseException e) {
                LOG.error(e.getMessage(), e);
            }
        }
        return sent;
    }

    private Map<Integer, WebsocketEventConsumer> evMap = new HashMap<Integer, WebsocketEventConsumer>();

    private WebsocketEventConsumer getEventConsumer(int channelId) {
        return evMap.computeIfAbsent(channelId, key -> new WebsocketEventConsumer(key));
    }

    @Override
    public ApiResponse handleApiView(String name, JSONObject params) throws ApiException {
        ApiResponse result;

        if (VIEW_CHANNELS.equals(name)) {
            ApiResponseList resultList = new ApiResponseList(name);
            try {
                List<WebSocketChannelDTO> channels = extension.getChannels(new WebSocketChannelDTO());
                for (WebSocketChannelDTO channel : channels) {
                    Map<String, String> map = new HashMap<String, String>();
                    map.put("id", Integer.toString(channel.id));
                    map.put("displayName", channel.toString());
                    map.put("connected", Boolean.toString(channel.isConnected()));
                    map.put("inScope", Boolean.toString(channel.isInScope()));
                    map.put("contextUrl", channel.getContextUrl());
                    map.put("fullUrl", channel.getFullUri());
                    if (channel.getHandshakeReference() != null) {
                        map.put("handshakeHistoryId", Integer.toString(channel.getHandshakeReference().getHistoryId()));
                    }
                    resultList.addItem(new ApiResponseSet<String>("channel", map));
                }
                result = resultList;
            } catch (DatabaseException e) {
                LOG.error(e.getMessage(), e);
                throw new ApiException(ApiException.Type.INTERNAL_ERROR);
            }
        } else if (VIEW_MESSAGE.equals(name)) {
            try {
                WebSocketMessageDTO message = extension.getWebsocketMessage(
                        ApiUtils.getIntParam(params, PARAM_MESSAGE_ID), 
                        ApiUtils.getIntParam(params, PARAM_CHANNEL_ID));
                result = wsMessageToResult(message, true);
            } catch (DatabaseException e) {
                LOG.error(e.getMessage(), e);
                throw new ApiException(ApiException.Type.INTERNAL_ERROR);
            }
        } else if (VIEW_MESSAGES.equals(name)) {
            ApiResponseList resultList = new ApiResponseList(name);
            try {
                WebSocketMessageDTO criteria = new WebSocketMessageDTO();
                List<Integer> opcodes = null;
                List<Integer> inScopeChannelIds = null;
                WebSocketMessagesPayloadFilter webSocketMessagesPayloadFilter = null;
                int offset = this.getParam(params, PARAM_START, 0);
                int limit = this.getParam(params, PARAM_COUNT, 0);
                int payloadPreviewLength = this.getParam(params, PARAM_PAYLOAD_PREVIEW_LENGTH, 1024);
                if (offset < 0) {
                    throw new ApiException(ApiException.Type.ILLEGAL_PARAMETER, PARAM_START);
                }

                if (params.containsKey(PARAM_CHANNEL_ID)) {
                    inScopeChannelIds = new ArrayList<Integer>();
                    inScopeChannelIds.add(params.getInt(PARAM_CHANNEL_ID));
                }

                List<WebSocketMessageDTO> messages = extension
                        .getWebsocketMessages(criteria, opcodes, inScopeChannelIds, webSocketMessagesPayloadFilter, offset, limit, payloadPreviewLength);
                for (WebSocketMessageDTO message : messages) {
                    resultList.addItem(wsMessageToResult(message, false));
                }
                result = resultList;
            } catch (DatabaseException e) {
                LOG.error(e.getMessage(), e);
                throw new ApiException(ApiException.Type.INTERNAL_ERROR);
            }
        } else {
            throw new ApiException(ApiException.Type.BAD_VIEW);
        }

        return result;
    }

    private ApiResponseSet<String> wsMessageToResult(WebSocketMessageDTO message, boolean fullPayload) {
        Map<String, String> map = new HashMap<String, String>();
        map.put("id", Integer.toString(message.id));
        map.put("opcode", Integer.toString(message.opcode));
        map.put("opcodeString", message.readableOpcode);
        map.put("timestamp", Long.toString(message.timestamp));
        map.put("outgoing", Boolean.toString(message.isOutgoing));
        map.put("channelId", Integer.toString(message.channel.id));
        map.put("messageId", Integer.toString(message.id));
        map.put("payloadLength", Integer.toString(message.payloadLength));
        if (fullPayload) {
            if (message.payload instanceof String) {
                map.put("payload", (String) message.payload);
            } else if (message.payload instanceof byte[]) {
                map.put("payload", Hex.encodeHexString((byte[]) message.payload));
            } else {
                try {
                    String payloadFragment = message.getReadablePayload();
                    map.put("payload", payloadFragment);
                } catch (InvalidUtf8Exception e) {
                    LOG.warn(e.getMessage(), e);
                }
            }
        } else {
            try {
                String payloadFragment = message.getReadablePayload();
                map.put("payloadFragment", payloadFragment);
            } catch (InvalidUtf8Exception e) {
                // Ignore as its just a summary
            }
        }

        return new ApiResponseSet<String>("message", map);
    }

    @Override
    public ApiResponse handleApiAction(String name, JSONObject params) throws ApiException {
        switch (name) {
        case ACTION_SEND_TEXT_MESSAGE:
            try {
                int channelId = params.getInt(PARAM_CHANNEL_ID);
                WebSocketProxy proxy = extension.getWebSocketProxy(channelId);
                if (proxy != null) {
                    this.sendWebSocketMessage(
                            proxy,
                            params.getBoolean(PARAM_OUTGOING),
                            params.getString(PARAM_MESSAGE));
                } else {
                    throw new ApiException(ApiException.Type.DOES_NOT_EXIST, "channelId: " + channelId);
                }
            } catch (IOException e) {
                LOG.warn(e.getMessage(), e);
                throw new ApiException(ApiException.Type.INTERNAL_ERROR, e.getMessage());
            }
            break;

        default:
            throw new ApiException(ApiException.Type.BAD_ACTION);
        }

        return ApiResponseElement.OK;
    }

    private class WebsocketEventConsumer implements EventConsumer {

        private int channelId;
        private Set<String> publisherNames;

        protected WebsocketEventConsumer(int channelId) {
            this.channelId = channelId;
            this.publisherNames = new HashSet<>();
        }

        public void addPublisherName(String name) {
            publisherNames.add(name);
        }

        public void removePublisherName(String name) {
            publisherNames.remove(name);
        }

        public Set<String> getPublisherNames() {
            return publisherNames;
        }

        @Override
        public void eventReceived(Event ev) {
            JSONObject json = new JSONObject();
            json.put("event.type", ev.getEventType());
            json.put("event.publisher", ev.getPublisher().getPublisherName());
            Target target = ev.getTarget();
            if (target != null) {
                JSONObject jsonTarget = new JSONObject();
                List<StructuralNode> nodes = target.getStartNodes();
                if (nodes != null) {
                    JSONArray jsonNodes = new JSONArray();
                    for (StructuralNode node : nodes) {
                        if (node == null) {
                            continue;
                        }
                        jsonNodes.add(node.getURI().toString());
                    }
                    jsonTarget.put("target.nodes", jsonNodes);
                }
                if (target.getContext() != null) {
                    jsonTarget.put("target.context", target.getContext().getName());
                }
                jsonTarget.put("target.inScopeOnly", target.isInScopeOnly());
                jsonTarget.put("target.recurse", target.isRecurse());
                jsonTarget.put("target.maxChildren", target.getMaxChildren());
                jsonTarget.put("target.maxDepth", target.getMaxDepth());
                json.put("event.target", jsonTarget);
            }
            // Can't use json.putAll as that performs auto json conversion, which we dont want
            for ( Entry<String, String> entry : ev.getParameters().entrySet()) {
                try {
                    JSONSerializer.toJSON(entry.getValue());
                    // Its valid JSON so escape
                    json.put(entry.getKey(), "'" + entry.getValue() + "'");
                } catch (JSONException e) {
                    // Its not a valid JSON object so can add as is
                    json.put(entry.getKey(), entry.getValue());
                }
            }
            try {
                sendWebSocketMessage(channelId, false, json.toString());
            } catch (SocketException e) {
                LOG.debug("Failed to dispatch event:", e);
                removeEventConsumer(this);
            } catch (IOException e) {
                LOG.error(e.getMessage(), e);
            }
        }
    }
}
