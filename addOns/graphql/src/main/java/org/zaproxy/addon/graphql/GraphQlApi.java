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
import net.sf.json.JSONObject;
import org.apache.commons.httpclient.URIException;
import org.apache.log4j.Logger;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.extension.api.ApiAction;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.extension.api.ApiImplementor;
import org.zaproxy.zap.extension.api.ApiResponse;
import org.zaproxy.zap.extension.api.ApiResponseElement;

public class GraphQlApi extends ApiImplementor {

    private static final String PREFIX = "graphql";
    private static final String ACTION_IMPORT_FILE = "importFile";
    private static final String ACTION_IMPORT_URL = "importUrl";
    private static final String PARAM_FILE = "file";
    private static final String PARAM_URL = "url";
    private static final String PARAM_ENDPOINT = "endurl";

    private static final Logger LOG = Logger.getLogger(GraphQlApi.class);

    public GraphQlApi() {
        this.addApiAction(
                new ApiAction(ACTION_IMPORT_FILE, new String[] {PARAM_ENDPOINT, PARAM_FILE}));
        this.addApiAction(
                new ApiAction(
                        ACTION_IMPORT_URL,
                        new String[] {PARAM_ENDPOINT},
                        new String[] {PARAM_URL}));
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

    private void importFile(JSONObject params) throws ApiException {
        try {
            GraphQlParser parser =
                    new GraphQlParser(
                            params.getString(PARAM_ENDPOINT),
                            HttpSender.MANUAL_REQUEST_INITIATOR,
                            true);
            parser.importFile(params.getString(PARAM_FILE));
        } catch (URIException e) {
            throw new ApiException(ApiException.Type.ILLEGAL_PARAMETER, e.getMessage());
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
