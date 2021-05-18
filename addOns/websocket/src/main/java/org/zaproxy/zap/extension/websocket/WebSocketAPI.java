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
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import net.sf.json.JSON;
import net.sf.json.JSONArray;
import net.sf.json.JSONException;
import net.sf.json.JSONObject;
import net.sf.json.JSONSerializer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.control.Control;
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
import org.zaproxy.zap.extension.brk.ExtensionBreak;
import org.zaproxy.zap.extension.httppanel.Message;
import org.zaproxy.zap.extension.websocket.WebSocketProxy.Initiator;
import org.zaproxy.zap.extension.websocket.WebSocketProxy.State;
import org.zaproxy.zap.extension.websocket.ui.WebSocketMessagesPayloadFilter;
import org.zaproxy.zap.extension.websocket.utility.WebSocketUtils;
import org.zaproxy.zap.model.StructuralNode;
import org.zaproxy.zap.model.Target;
import org.zaproxy.zap.utils.ApiUtils;

public class WebSocketAPI extends ApiImplementor {

    private static final String API_URL = "https://" + API.API_DOMAIN;

    private static final String PREFIX = "websocket";

    private ExtensionWebSocket extension;

    private static final String VIEW_CHANNELS = "channels";
    private static final String VIEW_MESSAGE = "message";
    private static final String VIEW_MESSAGES = "messages";
    private static final String VIEW_BREAK_TEXT_MESSAGE = "breakTextMessage";

    private static final String ACTION_SEND_TEXT_MESSAGE = "sendTextMessage";
    private static final String ACTION_SET_BREAK_TEXT_MESSAGE = "setBreakTextMessage";

    private static final String PARAM_COUNT = "count";
    private static final String PARAM_START = "start";
    private static final String PARAM_PAYLOAD_PREVIEW_LENGTH = "payloadPreviewLength";
    private static final String PARAM_CHANNEL_ID = "channelId";
    private static final String PARAM_MESSAGE_ID = "messageId";
    private static final String PARAM_OUTGOING = "outgoing";
    private static final String PARAM_MESSAGE = "message";

    private static final Logger LOG = LogManager.getLogger(WebSocketAPI.class);

    private WebSocketObserver observer;

    private String callbackUrl;

    /** Provided only for API client generator usage. */
    public WebSocketAPI() {
        this(null);
    }

    public WebSocketAPI(ExtensionWebSocket extension) {
        this.extension = extension;

        this.addApiView(new ApiView(VIEW_CHANNELS));
        this.addApiView(
                new ApiView(VIEW_MESSAGE, new String[] {PARAM_CHANNEL_ID, PARAM_MESSAGE_ID}));
        this.addApiView(
                new ApiView(
                        VIEW_MESSAGES,
                        null,
                        new String[] {
                            PARAM_CHANNEL_ID, PARAM_START, PARAM_COUNT, PARAM_PAYLOAD_PREVIEW_LENGTH
                        }));
        this.addApiView(new ApiView(VIEW_BREAK_TEXT_MESSAGE));

        this.addApiAction(
                new ApiAction(
                        ACTION_SEND_TEXT_MESSAGE,
                        new String[] {PARAM_CHANNEL_ID, PARAM_OUTGOING, PARAM_MESSAGE}));

        this.addApiAction(
                new ApiAction(
                        ACTION_SET_BREAK_TEXT_MESSAGE,
                        new String[] {PARAM_MESSAGE, PARAM_OUTGOING}));

        callbackUrl = API.getInstance().getCallBackUrl(this, API_URL);
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
            LOG.debug("callback url = {}", msg.getRequestHeader().getURI());

            String connectionHeader = msg.getRequestHeader().getHeader(HttpHeader.CONNECTION);
            String upgradeHeader = msg.getRequestHeader().getHeader("upgrade");

            if (connectionHeader != null && connectionHeader.toLowerCase().contains("upgrade")) {
                if (upgradeHeader != null && upgradeHeader.equalsIgnoreCase("websocket")) {
                    // Check Origin in case the randomly generated callback URL is accidentally
                    // leaked.
                    String origin = msg.getRequestHeader().getHeader("Origin");
                    if (!API_URL.equals(origin)) {
                        LOG.warn(
                                "Rejecting WebSocket connection, the Origin [{}] did not match [{}]",
                                origin,
                                API_URL);
                        msg.setResponseHeader("HTTP/1.1 403 Forbidden");
                        return "";
                    }
                    // Respond to handshake
                    msg.setResponseHeader(
                            API.getDefaultResponseHeader("101 Switching Protocols", null, 0));
                    msg.getResponseHeader().setHeader(HttpHeader.CONTENT_TYPE, null);
                    msg.getResponseHeader().setHeader(HttpHeader.CONNECTION, "Upgrade");
                    msg.getResponseHeader().setHeader("Upgrade", "websocket");

                    String secWebSocketKey = msg.getRequestHeader().getHeader("Sec-WebSocket-Key");
                    msg.getResponseHeader()
                            .setHeader(
                                    "Sec-WebSocket-Accept",
                                    WebSocketUtils.encodeWebSocketKey(secWebSocketKey));
                }
            }
            return "";
        } catch (Exception e) {
            throw new ApiException(
                    ApiException.Type.URL_NOT_FOUND, msg.getRequestHeader().getURI().toString());
        }
    }

    protected WebSocketObserver getWebSocketObserver() {
        if (observer == null) {
            observer =
                    new WebSocketObserver() {

                        @Override
                        public int getObservingOrder() {
                            // We want this to be after all of the built in observers
                            return 1000;
                        }

                        @Override
                        public boolean onMessageFrame(int channelId, WebSocketMessage message) {
                            WebSocketProxy proxy = extension.getWebSocketProxy(channelId);
                            if (proxy == null || !proxy.isAllowAPI()) {
                                // Shouldnt happen, but just to be safe
                                return false;
                            }
                            JSONObject json = null;
                            try {
                                if (WebSocketMessage.isControl(message.opcode)
                                        || !message.isFinished) {
                                    return false;
                                }
                                json = JSONObject.fromObject(message.getReadablePayload());
                                String component = json.getString("component");
                                String name = json.getString("name");
                                JSONObject params;
                                if (json.has("params")) {
                                    params = json.getJSONObject("params");
                                } else {
                                    params = new JSONObject();
                                }
                                JSON response = null;

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
                                    ApiImplementor impl =
                                            API.getInstance().getImplementors().get(component);
                                    if (impl == null) {
                                        throw new ApiException(ApiException.Type.NO_IMPLEMENTOR);
                                    }
                                    RequestType reqType =
                                            RequestType.valueOf(json.getString("type"));
                                    ApiResponse apiResp;

                                    switch (reqType) {
                                        case action:
                                            apiResp = impl.handleApiOptionAction(name, params);
                                            if (apiResp == null) {
                                                apiResp = impl.handleApiAction(name, params);
                                            }
                                            response = apiResp.toJSON();
                                            break;
                                        case view:
                                            apiResp = impl.handleApiOptionView(name, params);
                                            if (apiResp == null) {
                                                apiResp = impl.handleApiView(name, params);
                                            }
                                            response = apiResp.toJSON();
                                            break;
                                        case other:
                                            HttpMessage msg = new HttpMessage();
                                            msg = impl.handleApiOther(msg, name, params);
                                            apiResp =
                                                    new ApiResponseElement(
                                                            "response",
                                                            msg.getResponseBody().toString());
                                            response = apiResp.toJSON();
                                            break;
                                        case pconn:
                                            // Not currently supported
                                            throw new ApiException(
                                                    ApiException.Type.BAD_TYPE, reqType.name());
                                    }
                                }
                                if (response != null) {
                                    optionalResponse(proxy, response, json);
                                }
                            } catch (JSONException e) {
                                LOG.warn(e.getMessage(), e);
                                try {
                                    ApiException e2 =
                                            new ApiException(
                                                    ApiException.Type.ILLEGAL_PARAMETER,
                                                    e.getMessage());
                                    optionalResponse(proxy, e2, json);
                                } catch (IOException e1) {
                                    LOG.error(e.getMessage(), e);
                                }
                            } catch (ApiException e) {
                                try {
                                    optionalResponse(proxy, e, json);
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

    private void optionalResponse(WebSocketProxy proxy, JSON response, JSONObject request)
            throws IOException {
        if (request != null) {
            String id = request.optString("id", "");
            if (id.length() > 0) {
                // Only send a response if they've specified an id in the call
                sendWebSocketMessage(
                        proxy, responseWrapper(response, id, request.optString("caller", "")));
            }
        }
    }

    private void optionalResponse(WebSocketProxy proxy, ApiException ex, JSONObject request)
            throws IOException {
        // Not ideal, but atm the core does not expose the exception in JSON format
        optionalResponse(proxy, JSONObject.fromObject(ex.toString(Format.JSON, true)), request);
    }

    private String responseWrapper(JSON response, String id, String caller) {
        // OK, so its nasty wrapping JSON using strings, but the net.sf.json classes do way too much
        // auto conversion from strings that are valid JSON to JSON objects - this has proved to be
        // the safest option.
        StringBuilder sb = new StringBuilder();
        sb.append("{ \"id\": \"");
        sb.append(id);
        sb.append("\", ");
        if (caller.length() > 0) {
            sb.append("caller\": \"");
            sb.append(caller);
            sb.append("\", ");
        }
        sb.append("\"response\": ");
        sb.append(response.toString());
        sb.append(" }");
        return sb.toString();
    }

    private void removeEventConsumer(WebsocketEventConsumer consumer) {
        if (consumer == null) {
            return;
        }

        // TODO replace the sync block and loop with:
        // ZAP.getEventBus().unregisterConsumer(consumer);
        // once available in targeted ZAP version.
        synchronized (consumer.getPublisherNames()) {
            for (String publisherName : consumer.getPublisherNames()) {
                ZAP.getEventBus().unregisterConsumer(consumer, publisherName);
            }
        }
    }

    private boolean sendWebSocketMessage(int channelId, boolean outgoing, String message)
            throws IOException {
        WebSocketProxy proxy = extension.getWebSocketProxy(channelId);
        if (proxy != null) {
            return sendWebSocketMessage(proxy, outgoing, message);
        }
        return false;
    }

    private boolean sendWebSocketMessage(WebSocketProxy proxy, String message) throws IOException {
        return this.sendWebSocketMessage(proxy, false, message);
    }

    private boolean sendWebSocketMessage(WebSocketProxy proxy, boolean outgoing, String message)
            throws IOException {
        WebSocketMessageDTO resp = new WebSocketMessageDTO();
        resp.setChannel(proxy.getDTO());
        resp.setPayload(message);
        resp.setPayloadLength(message.length());
        resp.setOpcode(WebSocketMessage.OPCODE_TEXT);
        resp.setOutgoing(outgoing);
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

    private Map<Integer, WebsocketEventConsumer> evMap =
            Collections.synchronizedMap(new HashMap<>());

    private WebsocketEventConsumer getEventConsumer(int channelId) {
        return evMap.computeIfAbsent(channelId, WebsocketEventConsumer::new);
    }

    @Override
    public ApiResponse handleApiView(String name, JSONObject params) throws ApiException {
        ApiResponse result;

        if (VIEW_CHANNELS.equals(name)) {
            ApiResponseList resultList = new ApiResponseList(name);
            try {
                List<WebSocketChannelDTO> channels =
                        extension.getChannels(new WebSocketChannelDTO());
                for (WebSocketChannelDTO channel : channels) {
                    Map<String, String> map = new HashMap<>();
                    map.put("id", Integer.toString(channel.getId()));
                    map.put("displayName", channel.toString());
                    map.put("connected", Boolean.toString(channel.isConnected()));
                    map.put("inScope", Boolean.toString(channel.isInScope()));
                    map.put("contextUrl", channel.getContextUrl());
                    map.put("fullUrl", channel.getFullUri());
                    if (channel.getHandshakeReference() != null) {
                        map.put(
                                "handshakeHistoryId",
                                Integer.toString(channel.getHandshakeReference().getHistoryId()));
                    }
                    resultList.addItem(new ApiResponseSet<>("channel", map));
                }
                result = resultList;
            } catch (DatabaseException e) {
                LOG.error(e.getMessage(), e);
                throw new ApiException(ApiException.Type.INTERNAL_ERROR);
            }
        } else if (VIEW_MESSAGE.equals(name)) {
            try {
                WebSocketMessageDTO message =
                        extension.getWebsocketMessage(
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
                int payloadPreviewLength =
                        this.getParam(params, PARAM_PAYLOAD_PREVIEW_LENGTH, 1024);
                if (offset < 0) {
                    throw new ApiException(ApiException.Type.ILLEGAL_PARAMETER, PARAM_START);
                }

                if (params.containsKey(PARAM_CHANNEL_ID)) {
                    inScopeChannelIds = new ArrayList<>();
                    inScopeChannelIds.add(params.getInt(PARAM_CHANNEL_ID));
                }

                List<WebSocketMessageDTO> messages =
                        extension.getWebsocketMessages(
                                criteria,
                                opcodes,
                                inScopeChannelIds,
                                webSocketMessagesPayloadFilter,
                                offset,
                                limit,
                                payloadPreviewLength);
                for (WebSocketMessageDTO message : messages) {
                    resultList.addItem(wsMessageToResult(message, false));
                }
                result = resultList;
            } catch (DatabaseException e) {
                LOG.error(e.getMessage(), e);
                throw new ApiException(ApiException.Type.INTERNAL_ERROR);
            }
        } else if (VIEW_BREAK_TEXT_MESSAGE.equals(name)) {
            ExtensionBreak extBreak =
                    Control.getSingleton().getExtensionLoader().getExtension(ExtensionBreak.class);
            if (extBreak == null) {
                throw new ApiException(
                        ApiException.Type.INTERNAL_ERROR, "ExtensionBreak not present");
            }
            Message msg = extBreak.getBreakpointManagementInterface().getMessage();

            if (msg == null) {
                throw new ApiException(
                        ApiException.Type.ILLEGAL_PARAMETER, "No currently intercepted message");
            } else if (msg instanceof WebSocketMessageDTO) {
                WebSocketMessageDTO ws = (WebSocketMessageDTO) msg;
                result = new ApiResponseElement(PARAM_MESSAGE, ws.getPayloadAsString());
            } else {
                throw new ApiException(
                        ApiException.Type.ILLEGAL_PARAMETER,
                        "Intercepted message is not of the right type "
                                + msg.getClass().getCanonicalName());
            }
        } else {
            throw new ApiException(ApiException.Type.BAD_VIEW);
        }

        return result;
    }

    private ApiResponseSet<String> wsMessageToResult(
            WebSocketMessageDTO message, boolean fullPayload) {
        return new ApiResponseSet<>("message", message.toMap(fullPayload));
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
                        throw new ApiException(
                                ApiException.Type.DOES_NOT_EXIST, "channelId: " + channelId);
                    }
                } catch (IOException e) {
                    LOG.warn(e.getMessage(), e);
                    throw new ApiException(ApiException.Type.INTERNAL_ERROR, e.getMessage());
                }
                break;

            case ACTION_SET_BREAK_TEXT_MESSAGE:
                ExtensionBreak extBreak =
                        Control.getSingleton()
                                .getExtensionLoader()
                                .getExtension(ExtensionBreak.class);
                if (extBreak == null) {
                    throw new ApiException(
                            ApiException.Type.INTERNAL_ERROR, "ExtensionBreak not present");
                }
                Message msg = extBreak.getBreakpointManagementInterface().getMessage();

                if (msg == null) {
                    throw new ApiException(
                            ApiException.Type.ILLEGAL_PARAMETER,
                            "No currently intercepted message");
                } else if (msg instanceof WebSocketMessageDTO) {
                    WebSocketMessageDTO ws = (WebSocketMessageDTO) msg;
                    ws.setPayload(params.optString(PARAM_MESSAGE, ""));
                    extBreak.getBreakpointManagementInterface()
                            .setMessage(ws, params.getBoolean(PARAM_OUTGOING));
                } else {
                    throw new ApiException(
                            ApiException.Type.ILLEGAL_PARAMETER,
                            "Intercepted message is not of the right type "
                                    + msg.getClass().getCanonicalName());
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
            this.publisherNames = Collections.synchronizedSet(new HashSet<>());
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

            if (ev.getParameters() != null) {
                // Can't use json.putAll as that performs auto json conversion, which we dont want
                for (Entry<String, String> entry : ev.getParameters().entrySet()) {
                    try {
                        JSONSerializer.toJSON(entry.getValue());
                        // Its valid JSON so escape
                        json.put(entry.getKey(), "'" + entry.getValue() + "'");
                    } catch (JSONException e) {
                        // Its not a valid JSON object so can add as is
                        json.put(entry.getKey(), entry.getValue());
                    }
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
