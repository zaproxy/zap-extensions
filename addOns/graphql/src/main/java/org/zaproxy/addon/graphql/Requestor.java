/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
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
package org.zaproxy.addon.graphql;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import net.sf.json.JSONObject;
import org.apache.commons.httpclient.URI;
import org.apache.log4j.Logger;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.network.HttpRedirectionValidator;
import org.zaproxy.zap.network.HttpRequestBody;
import org.zaproxy.zap.network.HttpRequestConfig;

public class Requestor {

    private final int initiator;
    private final URI endpointUrl;
    private List<RequesterListener> listeners = new ArrayList<RequesterListener>();
    private HttpSender sender;
    private final HttpRequestConfig requestConfig;
    private static final Logger LOG = Logger.getLogger(Requestor.class);
    private static final String GRAPHQL_CONTENT_TYPE = "application/graphql";

    public Requestor(URI endpointUrl, int initiator) {
        this.endpointUrl = endpointUrl;
        this.initiator = initiator;
        sender =
                new HttpSender(
                        Model.getSingleton().getOptionsParam().getConnectionParam(),
                        true,
                        initiator);
        requestConfig =
                HttpRequestConfig.builder().setRedirectionValidator(new MessageHandler()).build();
    }

    private HttpMessage sendQueryByGet(String query, String variables) {
        try {
            String updatedEndpointUrl =
                    endpointUrl
                            + "?query="
                            + URLEncoder.encode(query, StandardCharsets.UTF_8.toString());
            if (!variables.isEmpty()) {
                updatedEndpointUrl +=
                        "?variables="
                                + URLEncoder.encode(variables, StandardCharsets.UTF_8.toString());
            }

            URI url = UrlBuilder.build(updatedEndpointUrl);
            HttpMessage message = new HttpMessage(url);
            send(message);
            return message;
        } catch (IOException e) {
            LOG.warn(e.getMessage());
        }
        return null;
    }

    private HttpMessage sendQueryByGraphQlPost(String query, String variables) {
        try {
            String updatedEndpointUrl = endpointUrl.toString();
            if (!variables.isEmpty()) {
                updatedEndpointUrl +=
                        "?variables="
                                + URLEncoder.encode(variables, StandardCharsets.UTF_8.toString());
            }
            URI url = UrlBuilder.build(updatedEndpointUrl);
            HttpRequestBody msgBody = new HttpRequestBody(query);
            HttpRequestHeader msgHeader =
                    new HttpRequestHeader(HttpRequestHeader.POST, url, HttpHeader.HTTP11);
            msgHeader.setHeader("Accept", HttpHeader.JSON_CONTENT_TYPE);
            msgHeader.setHeader(HttpHeader.CONTENT_TYPE, GRAPHQL_CONTENT_TYPE);
            msgHeader.setContentLength(msgBody.length());

            HttpMessage message = new HttpMessage(msgHeader, msgBody);
            send(message);
            return message;
        } catch (IOException e) {
            LOG.warn(e.getMessage());
        }
        return null;
    }

    private HttpMessage sendQueryByJsonPost(String query, String variables) {
        try {
            JSONObject msgBodyJson = new JSONObject();
            msgBodyJson.put("query", query);
            if (!variables.isEmpty()) {
                msgBodyJson.put("variables", variables);
            }
            HttpRequestBody msgBody = new HttpRequestBody(msgBodyJson.toString());

            HttpRequestHeader msgHeader =
                    new HttpRequestHeader(HttpRequestHeader.POST, endpointUrl, HttpHeader.HTTP11);
            msgHeader.setHeader("Accept", HttpHeader.JSON_CONTENT_TYPE);
            msgHeader.setHeader(HttpHeader.CONTENT_TYPE, HttpHeader.JSON_CONTENT_TYPE);
            msgHeader.setContentLength(msgBody.length());

            HttpMessage message = new HttpMessage(msgHeader, msgBody);
            send(message);
            return message;
        } catch (IOException e) {
            LOG.warn(e.getMessage(), e);
        }
        return null;
    }

    public HttpMessage sendQuery(String query, GraphQlParam.RequestMethodOption method) {
        return sendQuery(query, "", method);
    }

    public HttpMessage sendQuery(
            String query, String variables, GraphQlParam.RequestMethodOption method) {
        switch (method) {
            case GET:
                return sendQueryByGet(query, variables);
            case POST_GRAPHQL:
                return sendQueryByGraphQlPost(query, variables);
            case POST_JSON:
            default:
                return sendQueryByJsonPost(query, variables);
        }
    }

    public void send(HttpMessage message) throws IOException {
        sender.sendAndReceive(message, requestConfig);
    }

    public void addListener(RequesterListener listener) {
        this.listeners.add(listener);
    }

    public void removeListener(RequesterListener listener) {
        this.listeners.remove(listener);
    }

    /** Notifies the {@link #listeners} of the messages sent. */
    private class MessageHandler implements HttpRedirectionValidator {

        @Override
        public void notifyMessageReceived(HttpMessage message) {
            for (RequesterListener listener : listeners) {
                try {
                    listener.handleMessage(message, initiator);
                } catch (Exception e) {
                    LOG.warn(e.getMessage(), e);
                }
            }
        }

        @Override
        public boolean isValid(URI redirection) {
            return true;
        }
    }
}
