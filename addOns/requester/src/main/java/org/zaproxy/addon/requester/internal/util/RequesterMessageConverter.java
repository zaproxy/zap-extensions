/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.addon.requester.internal.util;

import java.util.Map;
import net.sf.json.JSONObject;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.zaproxy.addon.requester.internal.exception.RequesterException;
import org.zaproxy.zap.extension.httppanel.Message;
import org.zaproxy.zap.network.HttpRequestBody;
import org.zaproxy.zap.network.HttpResponseBody;

/**
 * Requester message converter
 *
 * <p>Contains utilities for converting between json and message objects.
 *
 * <p>Used for serialization/deserialization of messages.
 */
public class RequesterMessageConverter {

    /**
     * Converts message to JSON
     *
     * @param message Message to be converted
     * @return JSON object
     */
    public static JSONObject toJsonObject(Message message) {
        Map<String, String> eventData = message.toEventData();
        JSONObject json = new JSONObject();
        for (Map.Entry<String, String> eventDataEntry : eventData.entrySet()) {
            json.put(eventDataEntry.getKey(), eventDataEntry.getValue());
        }
        return json;
    }

    /**
     * Converts JSON to message
     *
     * @param json JSON json
     * @param messageType Type of message
     * @return Message json
     */
    public static Message toMessage(JSONObject json, String messageType) {
        switch (messageType) {
            case HttpMessage.MESSAGE_TYPE:
                return toHttpMessage(json);
            default:
                throw new RequesterException(
                        String.format("Unsupported message type '%s'!", messageType));
        }
    }

    /**
     * Converts JSON to HTTP message
     *
     * @param json JSON object
     * @return HTTP Message object
     */
    public static HttpMessage toHttpMessage(JSONObject json) {
        try {
            return new HttpMessage(
                    getHttpRequestHeader(json),
                    getHttpRequestBody(json),
                    getHttpResponseHeader(json),
                    getHttpResponseBody(json));
        } catch (org.parosproxy.paros.network.HttpMalformedHeaderException | URIException e) {
            throw new RequesterException(e);
        }
    }

    private static HttpRequestHeader getHttpRequestHeader(JSONObject json)
            throws HttpMalformedHeaderException, URIException {
        if (json.containsKey(HttpMessage.EVENT_DATA_REQUEST_HEADER)) {
            return new HttpRequestHeader(json.getString(HttpMessage.EVENT_DATA_REQUEST_HEADER));
        }
        return new HttpRequestHeader(
                HttpRequestHeader.GET, new URI(RequesterUtil.DEFAULT_URL, true), HttpHeader.HTTP11);
    }

    private static HttpResponseHeader getHttpResponseHeader(JSONObject json)
            throws HttpMalformedHeaderException {
        if (json.containsKey(HttpMessage.EVENT_DATA_RESPONSE_HEADER)) {
            return new HttpResponseHeader(json.getString(HttpMessage.EVENT_DATA_RESPONSE_HEADER));
        }
        return new HttpResponseHeader();
    }

    private static HttpRequestBody getHttpRequestBody(JSONObject json) {
        if (json.containsKey(HttpMessage.EVENT_DATA_REQUEST_BODY)) {
            return new HttpRequestBody(json.getString(HttpMessage.EVENT_DATA_REQUEST_BODY));
        }
        return new HttpRequestBody();
    }

    private static HttpResponseBody getHttpResponseBody(JSONObject json) {
        if (json.containsKey(HttpMessage.EVENT_DATA_RESPONSE_BODY)) {
            return new HttpResponseBody(json.getString(HttpMessage.EVENT_DATA_RESPONSE_BODY));
        }
        return new HttpResponseBody();
    }

    private RequesterMessageConverter() {}
}
