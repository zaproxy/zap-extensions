/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
import net.sf.json.JSONObject;
import org.apache.commons.httpclient.URI;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.zap.network.HttpRequestBody;

public class GraphQlQueryMessageBuilder {

    private final URI endpointUrl;
    private static final String GRAPHQL_CONTENT_TYPE = "application/graphql";

    public GraphQlQueryMessageBuilder(URI endpointUrl) {
        this.endpointUrl = endpointUrl;
    }

    public HttpMessage buildQueryMessage(
            String query, String variables, GraphQlParam.RequestMethodOption method)
            throws IOException {
        return switch (method) {
            case GET -> buildGetQueryMessage(query, variables);
            case POST_GRAPHQL -> buildGraphQlPostQueryMessage(query, variables);
            case POST_JSON -> buildJsonPostQueryMessage(query, variables);
        };
    }

    private HttpMessage buildGetQueryMessage(String query, String variables) throws IOException {
        String updatedEndpointUrl =
                endpointUrl
                        + "?query="
                        + URLEncoder.encode(query, StandardCharsets.UTF_8.toString());
        if (!variables.isEmpty()) {
            updatedEndpointUrl +=
                    "&variables=" + URLEncoder.encode(variables, StandardCharsets.UTF_8.toString());
        }

        URI url = UrlBuilder.build(updatedEndpointUrl);
        return new HttpMessage(url);
    }

    private HttpMessage buildGraphQlPostQueryMessage(String query, String variables)
            throws IOException {
        String updatedEndpointUrl = endpointUrl.toString();
        if (!variables.isEmpty()) {
            updatedEndpointUrl +=
                    "?variables=" + URLEncoder.encode(variables, StandardCharsets.UTF_8.toString());
        }
        URI url = UrlBuilder.build(updatedEndpointUrl);
        HttpRequestBody msgBody = new HttpRequestBody(query);
        HttpRequestHeader msgHeader =
                new HttpRequestHeader(HttpRequestHeader.POST, url, HttpHeader.HTTP11);
        msgHeader.setHeader("Accept", HttpHeader.JSON_CONTENT_TYPE);
        msgHeader.setHeader(HttpHeader.CONTENT_TYPE, GRAPHQL_CONTENT_TYPE);
        msgHeader.setContentLength(msgBody.length());

        return new HttpMessage(msgHeader, msgBody);
    }

    private HttpMessage buildJsonPostQueryMessage(String query, String variables)
            throws IOException {
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
        return new HttpMessage(msgHeader, msgBody);
    }
}
