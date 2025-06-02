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
package org.zaproxy.addon.graphql;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.TreeSet;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.core.scanner.NameValuePair;
import org.parosproxy.paros.core.scanner.Variant;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.zap.model.SessionStructure;

public class VariantGraphQl implements Variant {

    private static final Logger LOGGER = LogManager.getLogger(VariantGraphQl.class);
    private final InlineInjector injector = new InlineInjector();
    private final List<NameValuePair> params = new ArrayList<>();

    private static final String QUERY_KEY = "query";

    @Override
    public void setMessage(HttpMessage msg) {
        String query = getQuery(msg);
        if (query == null) {
            return;
        }
        params.clear();
        injector.extract(query)
                .forEach(
                        (name, value) ->
                                params.add(
                                        new NameValuePair(
                                                NameValuePair.TYPE_GRAPHQL_INLINE,
                                                name,
                                                value,
                                                params.size())));
    }

    @Override
    public List<NameValuePair> getParamList() {
        return params;
    }

    @Override
    public String setEscapedParameter(
            HttpMessage msg, NameValuePair originalPair, String param, String value) {
        return setParameter(msg, originalPair, param, value);
    }

    private String getQuery(HttpMessage msg) {
        HttpRequestHeader header = msg.getRequestHeader();
        String body = msg.getRequestBody().toString();
        String query = null;

        if (HttpRequestHeader.POST.equals(header.getMethod())) {
            if (body.isEmpty()) {
                return null;
            }
            var contentTypeHeader = header.getNormalisedContentTypeValue();
            if (contentTypeHeader == null
                    || contentTypeHeader.contains(HttpHeader.JSON_CONTENT_TYPE)) {
                try {
                    JSONObject json = JSONObject.fromObject(body);
                    if (json.has(QUERY_KEY)) {
                        query = json.get(QUERY_KEY).toString();
                    }
                } catch (Exception e) {
                    if (contentTypeHeader != null) {
                        try {
                            // If its a valid JSON array then its not a GraphQl query, so no need to
                            // report a potential issue
                            JSONArray.fromObject(body);
                        } catch (Exception e1) {
                            LOGGER.debug("Parsing message body failed: {}", e.getMessage());
                        }
                    }
                    return null;
                }
            } else if (contentTypeHeader.contains("application/graphql")) {
                query = body;
            }
        } else if (HttpRequestHeader.GET.equals(header.getMethod())) {
            for (HtmlParameter param : msg.getUrlParams()) {
                if (QUERY_KEY.equals(param.getName())) {
                    query = param.getValue();
                    break;
                }
            }
        }
        return injector.validateQuery(query) ? query : null;
    }

    private void setQuery(HttpMessage msg, String query) {
        HttpRequestHeader header = msg.getRequestHeader();
        String body = msg.getRequestBody().toString();

        if (HttpRequestHeader.POST.equals(header.getMethod())) {
            String contentTypeHeader = header.getNormalisedContentTypeValue();
            if (!body.isEmpty() && contentTypeHeader == null
                    || contentTypeHeader.contains(HttpHeader.JSON_CONTENT_TYPE)) {
                try {
                    JSONObject json = JSONObject.fromObject(body);
                    json.put(QUERY_KEY, query);
                    msg.setRequestBody(json.toString());
                    msg.getRequestHeader().setContentLength(msg.getRequestBody().length());
                } catch (Exception e) {
                    if (contentTypeHeader != null) {
                        LOGGER.warn("Parsing message body failed: {}", e.getMessage());
                    }
                }
            } else if (contentTypeHeader.contains("application/graphql")) {
                msg.setRequestBody(query);
                msg.getRequestHeader().setContentLength(msg.getRequestBody().length());
            }
        } else if (HttpRequestHeader.GET.equals(header.getMethod())) {
            TreeSet<HtmlParameter> urlParams = msg.getUrlParams();
            for (HtmlParameter param : urlParams) {
                if (QUERY_KEY.equals(param.getName())) {
                    param.setValue(query);
                    break;
                }
            }
            msg.setGetParams(urlParams);
        }
    }

    @Override
    public String setParameter(
            HttpMessage msg, NameValuePair originalPair, String param, String value) {
        String query = getQuery(msg);
        if (query == null) {
            return null;
        }
        try {
            setQuery(msg, injector.inject(query, param, value));
            return value;
        } catch (Exception e) {
            LOGGER.warn("Failed to set parameter in GraphQL message: {}", e.getMessage());
            return null;
        }
    }

    @Override
    public String getLeafName(String nodeName, HttpMessage msg) {
        if (params.isEmpty()) {
            return null;
        }
        return SessionStructure.getLeafName(nodeName, msg, params);
    }

    @Override
    public List<String> getTreePath(HttpMessage msg) throws URIException {
        String query = getQuery(msg);
        if (query == null) {
            return null;
        }
        URI uri = msg.getRequestHeader().getURI();
        String[] path = uri.getPath() != null ? uri.getPath().split("/") : new String[0];
        List<String> treePath = new ArrayList<>(path.length + 1);
        Collections.addAll(treePath, path);
        treePath.add(injector.extractOperations(query));
        treePath.add(injector.getNodeName(query));
        return treePath;
    }
}
