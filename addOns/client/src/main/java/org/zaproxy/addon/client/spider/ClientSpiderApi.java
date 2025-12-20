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

import java.util.List;
import net.sf.json.JSONObject;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.SiteNode;
import org.zaproxy.addon.client.ClientOptions;
import org.zaproxy.addon.client.ClientOptions.ScopeCheck;
import org.zaproxy.addon.client.ExtensionClientIntegration;
import org.zaproxy.zap.extension.api.ApiAction;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.extension.api.ApiException.Type;
import org.zaproxy.zap.extension.api.ApiImplementor;
import org.zaproxy.zap.extension.api.ApiResponse;
import org.zaproxy.zap.extension.api.ApiResponseElement;
import org.zaproxy.zap.extension.api.ApiView;
import org.zaproxy.zap.extension.selenium.Browser;
import org.zaproxy.zap.extension.users.ExtensionUserManagement;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.users.User;
import org.zaproxy.zap.utils.ApiUtils;

public class ClientSpiderApi extends ApiImplementor {

    private static final Logger LOGGER = LogManager.getLogger(ClientSpiderApi.class);

    private static final String PREFIX = "clientSpider";
    private static final String I18N_PREFIX = "client." + PREFIX;

    private static final String ACTION_START_SCAN = "scan";
    private static final String ACTION_STOP_SCAN = "stop";

    private static final String VIEW_STATUS = "status";

    private static final String PARAM_BROWSER = "browser";
    private static final String PARAM_CONTEXT_NAME = "contextName";
    private static final String PARAM_SCAN_ID = "scanId";
    private static final String PARAM_SUBTREE_ONLY = "subtreeOnly";
    private static final String PARAM_URL = "url";
    private static final String PARAM_USER_NAME = "userName";
    private static final String PARAM_MAX_CRAWL_DEPTH = "maxCrawlDepth";
    private static final String PARAM_PAGE_LOAD_TIME = "pageLoadTime";
    private static final String PARAM_NUMBER_OF_BROWSERS = "numberOfBrowsers";
    private static final String PARAM_SCOPE_CHECK = "scopeCheck";

    private final ExtensionClientIntegration extension;

    public ClientSpiderApi() {
        this(null);
    }

    public ClientSpiderApi(ExtensionClientIntegration extension) {
        this.extension = extension;

        addApiAction(
                new ApiAction(
                        ACTION_START_SCAN,
                        null,
                        List.of(
                                PARAM_BROWSER,
                                PARAM_URL,
                                PARAM_CONTEXT_NAME,
                                PARAM_USER_NAME,
                                PARAM_SUBTREE_ONLY,
                                PARAM_MAX_CRAWL_DEPTH,
                                PARAM_PAGE_LOAD_TIME,
                                PARAM_NUMBER_OF_BROWSERS,
                                PARAM_SCOPE_CHECK)));

        addApiAction(new ApiAction(ACTION_STOP_SCAN, List.of(PARAM_SCAN_ID)));

        addApiView(new ApiView(VIEW_STATUS, List.of(PARAM_SCAN_ID)));
    }

    @Override
    protected String getI18nPrefix() {
        return I18N_PREFIX;
    }

    @Override
    public String getPrefix() {
        return PREFIX;
    }

    @Override
    public ApiResponse handleApiAction(String name, JSONObject params) throws ApiException {
        LOGGER.debug("Request for handleApiAction: {} (params: {})", name, params);

        switch (name) {
            case ACTION_START_SCAN:
                return startScan(name, params);

            case ACTION_STOP_SCAN:
                extension.stopScan(getClientSpider(params).getScanId());
                return ApiResponseElement.OK;

            default:
                throw new ApiException(ApiException.Type.BAD_ACTION);
        }
    }

    private ApiResponse startScan(String name, JSONObject params) throws ApiException {
        String url = ApiUtils.getOptionalStringParam(params, PARAM_URL);

        Context context = null;
        if (params.containsKey(PARAM_CONTEXT_NAME)) {
            String contextName = params.getString(PARAM_CONTEXT_NAME);
            if (!contextName.isEmpty()) {
                context = ApiUtils.getContextByName(contextName);
            }
        }

        boolean validateUrl = true;
        if (url == null || url.isEmpty()) {
            url = getContextUrl(context);
            validateUrl = false;
        } else if (context != null && !context.isInContext(url)) {
            throw new ApiException(Type.URL_NOT_IN_CONTEXT, PARAM_URL);
        }

        if (validateUrl) {
            validateUrl(url);
        }

        validateMode(url, context, validateUrl);

        ClientOptions options = extension.getClientParam().clone();
        options.setBrowserId(getBrowser(params));

        if (params.containsKey(PARAM_MAX_CRAWL_DEPTH)) {
            options.setMaxDepth(ApiUtils.getIntParam(params, PARAM_MAX_CRAWL_DEPTH));
        }
        if (params.containsKey(PARAM_PAGE_LOAD_TIME)) {
            options.setPageLoadTimeInSecs(ApiUtils.getIntParam(params, PARAM_PAGE_LOAD_TIME));
        }
        if (params.containsKey(PARAM_NUMBER_OF_BROWSERS)) {
            options.setThreadCount(ApiUtils.getIntParam(params, PARAM_NUMBER_OF_BROWSERS));
        }
        if (params.containsKey(PARAM_SCOPE_CHECK)) {
            options.setScopeCheck(
                    ApiUtils.getOptionalEnumParam(params, PARAM_SCOPE_CHECK, ScopeCheck.class));
        }

        User user = getUser(params, context);

        try {
            int scanId =
                    extension.startScan(
                            url,
                            options,
                            context,
                            user,
                            getParam(params, PARAM_SUBTREE_ONLY, false));
            return new ApiResponseElement(name, Integer.toString(scanId));
        } catch (Exception e) {
            throw new ApiException(ApiException.Type.INTERNAL_ERROR, e);
        }
    }

    private static String getContextUrl(Context context) throws ApiException {
        if (context == null || !context.hasNodesInContextFromSiteTree()) {
            throw new ApiException(Type.MISSING_PARAMETER, PARAM_URL);
        }

        List<SiteNode> nodes = context.getNodesInContextFromSiteTree();
        if (nodes.isEmpty()) {
            throw new ApiException(Type.MISSING_PARAMETER, PARAM_URL);
        }

        return nodes.get(0).getHistoryReference().getURI().getEscapedURIReference();
    }

    private static void validateUrl(String url) throws ApiException {
        try {
            String scheme = new URI(url, true).getScheme();
            if (scheme == null
                    || (!scheme.equalsIgnoreCase("http") && !scheme.equalsIgnoreCase("https"))) {
                throw new ApiException(ApiException.Type.ILLEGAL_PARAMETER, PARAM_URL);
            }
        } catch (URIException e) {
            throw new ApiException(ApiException.Type.ILLEGAL_PARAMETER, PARAM_URL, e);
        }
    }

    private static void validateMode(String url, Context context, boolean validateUrl)
            throws ApiException {
        switch (Control.getSingleton().getMode()) {
            case safe:
                throw new ApiException(ApiException.Type.MODE_VIOLATION);

            case protect:
                if ((validateUrl && !Model.getSingleton().getSession().isInScope(url))
                        || (context != null && !context.isInScope())) {
                    throw new ApiException(ApiException.Type.MODE_VIOLATION);
                }
                break;

            case attack, standard:
            default:
                break;
        }
    }

    private static String getBrowser(JSONObject params) throws ApiException {
        String browserId = params.optString(PARAM_BROWSER);
        if (browserId.isEmpty()) {
            return Browser.FIREFOX_HEADLESS.getId();
        }

        Browser browser = Browser.getBrowserWithIdNoFailSafe(browserId);
        if (browser == null) {
            throw new ApiException(Type.ILLEGAL_PARAMETER, PARAM_BROWSER);
        }
        return browser.getId();
    }

    private static User getUser(JSONObject params, Context context) throws ApiException {
        String userName = params.optString(PARAM_USER_NAME);
        if (userName.isEmpty()) {
            return null;
        }

        if (context == null) {
            throw new ApiException(Type.MISSING_PARAMETER, PARAM_CONTEXT_NAME);
        }

        ExtensionUserManagement usersExtension =
                Control.getSingleton()
                        .getExtensionLoader()
                        .getExtension(ExtensionUserManagement.class);
        if (usersExtension == null) {
            throw new ApiException(Type.NO_IMPLEMENTOR, ExtensionUserManagement.NAME);
        }
        return usersExtension.getContextUserAuthManager(context.getId()).getUsers().stream()
                .filter(e -> userName.equals(e.getName()))
                .findFirst()
                .orElseThrow(() -> new ApiException(Type.USER_NOT_FOUND, PARAM_USER_NAME));
    }

    @Override
    public ApiResponse handleApiView(String name, JSONObject params) throws ApiException {

        switch (name) {
            case VIEW_STATUS:
                ClientSpider scan = getClientSpider(params);
                int progress = scan.isStopped() ? 100 : Math.min(scan.getProgress(), 99);
                return new ApiResponseElement(name, Integer.toString(progress));

            default:
                throw new ApiException(ApiException.Type.BAD_VIEW);
        }
    }

    private ClientSpider getClientSpider(JSONObject params) throws ApiException {
        ClientSpider scan = extension.getScan(ApiUtils.getIntParam(params, PARAM_SCAN_ID));
        if (scan == null) {
            throw new ApiException(Type.ILLEGAL_PARAMETER, PARAM_SCAN_ID);
        }
        return scan;
    }
}
