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
package org.zaproxy.addon.client.spider;

import net.sf.json.JSONObject;
import org.apache.commons.httpclient.URIException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.addon.client.ClientOptions;
import org.zaproxy.addon.client.ExtensionClientIntegration;
import org.zaproxy.zap.extension.api.ApiAction;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.extension.api.ApiImplementor;
import org.zaproxy.zap.extension.api.ApiResponse;
import org.zaproxy.zap.extension.api.ApiResponseElement;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.users.User;
import org.zaproxy.zap.utils.ApiUtils;

public class ClientSpiderAPI extends ApiImplementor {
    private static final Logger LOGGER = LogManager.getLogger(ClientSpiderAPI.class);

    /** The Constant PREFIX defining the name/prefix of the api. */
    private static final String PREFIX = "clientSpider";

    /** The Constant ACTION_START_SCAN that defines the action of starting a new scan. */
    private static final String ACTION_START_SCAN = "scan";

    /** The Constant ACTION_STOP_SCAN that defines the action of stopping a pending scan. */
    private static final String ACTION_STOP_SCAN = "stop";

    /** The Constant PARAM_URL that defines the parameter defining the url of the scan. */
    private static final String PARAM_URL = "url";

    private static final String PARAM_CONTEXT_NAME = "contextName";
    private static final String PARAM_RECURSE = "recurse";
    private static final String PARAM_SCAN_ID = "scanId";
    private static final String PARAM_MAX_CHILDREN = "maxChildren";
    private static final String PARAM_SUBTREE_ONLY = "subtreeOnly";

    /** The client extension. */
    private ExtensionClientIntegration extension;

    @Override
    public String getPrefix() {
        return PREFIX;
    }

    /**
     * Instantiates a new client spider API.
     *
     * @param extension the extension
     */
    public ClientSpiderAPI(ExtensionClientIntegration extension) {
        this.extension = extension;

        // Register the actions
        this.addApiAction(
                new ApiAction(
                        ACTION_START_SCAN,
                        null,
                        new String[] {
                            PARAM_URL,
                            PARAM_MAX_CHILDREN,
                            PARAM_RECURSE,
                            PARAM_CONTEXT_NAME,
                            PARAM_SUBTREE_ONLY
                        }));

        this.addApiAction(new ApiAction(ACTION_STOP_SCAN, null, new String[] {PARAM_SCAN_ID}));
    }

    @Override
    public ApiResponse handleApiAction(String name, JSONObject params) throws ApiException {
        LOGGER.debug("Request for handleApiAction: {} (params: {})", name, params);

        ClientSpider scan;
        int maxChildren = -1;
        Context context = null;

        switch (name) {
            case ACTION_START_SCAN:
                // The action is to start a new Scan
                String url = ApiUtils.getOptionalStringParam(params, PARAM_URL);
                if (params.containsKey(PARAM_MAX_CHILDREN)) {
                    String maxChildrenStr = params.getString(PARAM_MAX_CHILDREN);
                    if (maxChildrenStr != null && !maxChildrenStr.isEmpty()) {
                        try {
                            maxChildren = Integer.parseInt(maxChildrenStr);
                        } catch (NumberFormatException e) {
                            throw new ApiException(
                                    ApiException.Type.ILLEGAL_PARAMETER, PARAM_MAX_CHILDREN);
                        }
                    }
                }
                if (params.containsKey(PARAM_CONTEXT_NAME)) {
                    String contextName = params.getString(PARAM_CONTEXT_NAME);
                    if (!contextName.isEmpty()) {
                        context = ApiUtils.getContextByName(contextName);
                    }
                }

                User user = extension.getSelectedUser();

                ClientOptions options = this.extension.getClientParam();
                options.setMaxChildren(maxChildren);

                try {
                    int scanId =
                            extension.startScan(
                                    url,
                                    options,
                                    context,
                                    user,
                                    getParam(params, PARAM_SUBTREE_ONLY, false));
                    return new ApiResponseElement(name, Integer.toString(scanId));
                } catch (URIException e) {
                    throw new RuntimeException(e);
                }

            case ACTION_STOP_SCAN:
                // The action is to stop a scan using the spider scan controller
                scan = getClientSpiderScan(params);
                extension.stopScan(scan.getScanId());
                break;
            default:
                throw new ApiException(ApiException.Type.BAD_ACTION);
        }

        return ApiResponseElement.OK;
    }

    /**
     * Returns the specified GenericScanner2 or the last scan available.
     *
     * @param params the parameters of the API call
     * @return the GenericScanner2 with the given scan ID or, if not present, the last scan
     *     available
     * @throws ApiException if there's no scan with the given scan ID
     * @see #PARAM_SCAN_ID
     */
    private ClientSpider getClientSpiderScan(JSONObject params) throws ApiException {
        ClientSpider spiderScan;
        int id = getParam(params, PARAM_SCAN_ID, -1);
        if (id == -1) {
            spiderScan = this.extension.getSpiderScanController().getLastScan();
        } else {
            spiderScan = extension.getScan(id);
        }

        if (spiderScan == null) {
            throw new ApiException(ApiException.Type.DOES_NOT_EXIST, PARAM_SCAN_ID);
        }

        return spiderScan;
    }
}
