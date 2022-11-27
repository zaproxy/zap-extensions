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

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import net.sf.json.JSONObject;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.extension.api.ApiAction;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.extension.api.ApiImplementor;
import org.zaproxy.zap.extension.api.ApiOther;
import org.zaproxy.zap.extension.api.ApiResponse;
import org.zaproxy.zap.extension.api.ApiResponseElement;

public class GraphQlApi extends ApiImplementor {

    private static final String PREFIX = "graphql";
    private static final String ACTION_IMPORT_FILE = "importFile";
    private static final String ACTION_IMPORT_URL = "importUrl";
    private static final String PARAM_FILE = "file";
    private static final String PARAM_URL = "url";
    private static final String PARAM_ENDPOINT = "endurl";
    private static final String OTHER_GRAPHIQL = "graphiql";

    private static byte[] graphiqlHtml;

    public GraphQlApi() {
        this.addApiAction(
                new ApiAction(ACTION_IMPORT_FILE, new String[] {PARAM_ENDPOINT, PARAM_FILE}));
        this.addApiAction(
                new ApiAction(
                        ACTION_IMPORT_URL,
                        new String[] {PARAM_ENDPOINT},
                        new String[] {PARAM_URL}));
        this.addApiOthers(new ApiOther(OTHER_GRAPHIQL));
        this.addApiShortcut(OTHER_GRAPHIQL);
    }

    /**
     * Constructs a {@code GraphQlApi} with the given {@code options} exposed through the API.
     *
     * @param options the options that will be exposed through the API.
     */
    public GraphQlApi(GraphQlParam options) {
        this();
        addApiOptions(options);
    }

    @Override
    public String getPrefix() {
        return PREFIX;
    }

    @Override
    public ApiResponse handleApiAction(String name, JSONObject params) throws ApiException {
        switch (name) {
            case ACTION_IMPORT_FILE:
                importFile(params);
                break;
            case ACTION_IMPORT_URL:
                importUrl(params);
                break;
            default:
                throw new ApiException(ApiException.Type.BAD_ACTION);
        }

        return ApiResponseElement.OK;
    }

    @Override
    public HttpMessage handleShortcut(HttpMessage msg) throws ApiException {
        if (msg.getRequestHeader().getURI().getEscapedPath().startsWith("/" + OTHER_GRAPHIQL)) {
            return handleApiOther(msg, OTHER_GRAPHIQL, null);
        }
        throw new ApiException(
                ApiException.Type.URL_NOT_FOUND, msg.getRequestHeader().getURI().toString());
    }

    @Override
    public HttpMessage handleApiOther(HttpMessage msg, String name, JSONObject params)
            throws ApiException {
        if (!OTHER_GRAPHIQL.equals(name)) {
            throw new ApiException(ApiException.Type.BAD_OTHER);
        }
        msg.setResponseBody(getGraphiqlHtml());
        msg.getResponseHeader().setHeader("Content-Type", "text/html; charset=UTF-8");
        return msg;
    }

    private static byte[] getGraphiqlHtml() throws ApiException {
        if (graphiqlHtml != null) {
            return graphiqlHtml;
        }
        try (InputStream in = GraphQlApi.class.getResourceAsStream("resources/graphiql.html")) {
            if (in == null) {
                throw new ApiException(
                        ApiException.Type.INTERNAL_ERROR, "Unable to load GraphiQL.");
            }
            graphiqlHtml = in.readAllBytes();
            return graphiqlHtml;
        } catch (Exception e) {
            throw new ApiException(ApiException.Type.INTERNAL_ERROR, "Unable to load GraphiQL", e);
        }
    }

    private void importFile(JSONObject params) throws ApiException {
        try {
            GraphQlParser parser =
                    new GraphQlParser(
                            params.getString(PARAM_ENDPOINT),
                            HttpSender.MANUAL_REQUEST_INITIATOR,
                            true);
            parser.importFile(params.getString(PARAM_FILE));
        } catch (FileNotFoundException e) {
            throw new ApiException(ApiException.Type.DOES_NOT_EXIST, e.getMessage());
        } catch (IOException e) {
            throw new ApiException(ApiException.Type.ILLEGAL_PARAMETER, e.getMessage());
        }
    }

    private void importUrl(JSONObject params) throws ApiException {
        try {
            GraphQlParser parser =
                    new GraphQlParser(
                            params.getString(PARAM_ENDPOINT),
                            HttpSender.MANUAL_REQUEST_INITIATOR,
                            true);
            parser.addRequesterListener(new HistoryPersister());
            if (params.optString(PARAM_URL, "").isEmpty()) {
                parser.introspect();
            } else {
                parser.importUrl(params.optString(PARAM_URL));
            }
        } catch (IOException e) {
            throw new ApiException(ApiException.Type.ILLEGAL_PARAMETER, e.getMessage());
        }
    }
}
