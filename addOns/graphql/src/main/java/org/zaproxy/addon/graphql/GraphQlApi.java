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

import net.sf.json.JSONObject;
import org.apache.log4j.Logger;
import org.zaproxy.zap.extension.api.ApiAction;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.extension.api.ApiImplementor;
import org.zaproxy.zap.extension.api.ApiResponse;
import org.zaproxy.zap.extension.api.ApiResponseElement;

public class GraphQlApi extends ApiImplementor {

    private static final String PREFIX = "graphql";
    private static final String ACTION_IMPORT_FILE = "importFile";
    private static final String ACTION_IMPORT_URL = "importUrl";
    private static final String PARAM_URL = "url";
    private static final String PARAM_FILE = "file";
    private static final String PARAM_TARGET = "target";

    private static final Logger LOGGER = Logger.getLogger(GraphQlApi.class);
    private ExtensionGraphQl extension = null;

    /** Provided only for API client generator usage. */
    public GraphQlApi() {
        this(null);
    }

    public GraphQlApi(ExtensionGraphQl ext) {
        extension = ext;
        this.addApiAction(
                new ApiAction(
                        ACTION_IMPORT_FILE,
                        new String[] {PARAM_FILE},
                        new String[] {PARAM_TARGET}));
        this.addApiAction(new ApiAction(ACTION_IMPORT_URL, new String[] {PARAM_URL}));
    }

    @Override
    public String getPrefix() {
        return PREFIX;
    }

    @Override
    public ApiResponse handleApiAction(String name, JSONObject params) throws ApiException {
        switch (name) {
            case ACTION_IMPORT_FILE:
            case ACTION_IMPORT_URL:
                LOGGER.debug("Nothing to see here (yet) :)");
                break;

            default:
                throw new ApiException(ApiException.Type.BAD_ACTION);
        }

        return ApiResponseElement.OK;
    }
}
