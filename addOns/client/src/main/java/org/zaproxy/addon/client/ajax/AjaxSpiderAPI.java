/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.addon.client.ajax;

import net.sf.json.JSON;
import net.sf.json.JSONObject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.zaproxy.zap.extension.api.API;
import org.zaproxy.zap.extension.api.ApiAction;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.extension.api.ApiImplementor;
import org.zaproxy.zap.extension.api.ApiResponse;
import org.zaproxy.zap.extension.api.ApiResponseElement;
import org.zaproxy.zap.extension.api.ApiResponseList;
import org.zaproxy.zap.extension.api.ApiView;

/**
 * Stands in for the real {@code ajaxSpider} API when the AJAX Spider add-on is not installed,
 * translating requests and delegating to the real {@code clientSpider} API so that existing
 * scripts/clients keep working, running the Client Spider instead.
 *
 * <p>Only the actions/views that map cleanly onto the Client Spider are actually implemented; the
 * parts of the original API backed by concepts the Client Spider does not have (allowed resources,
 * excluded elements, per-message results) are still registered, for compatibility, but are no-ops -
 * they do nothing and always succeed with empty/zeroed data.
 */
public class AjaxSpiderAPI extends ApiImplementor {

    private static final Logger LOGGER = LogManager.getLogger(AjaxSpiderAPI.class);

    private static final String PREFIX = "ajaxSpider";

    private static final String ACTION_START_SCAN = "scan";
    private static final String ACTION_START_SCAN_AS_USER = "scanAsUser";
    private static final String ACTION_STOP_SCAN = "stop";

    // AJAX Spider only actions, not implemented, kept as no-ops for compatibility.
    private static final String ACTION_ADD_ALLOWED_RESOURCE = "addAllowedResource";
    private static final String ACTION_ADD_EXCLUDED_ELEMENT = "addExcludedElement";
    private static final String ACTION_MODIFY_EXCLUDED_ELEMENT = "modifyExcludedElement";
    private static final String ACTION_REMOVE_ALLOWED_RESOURCE = "removeAllowedResource";
    private static final String ACTION_REMOVE_EXCLUDED_ELEMENT = "removeExcludedElement";
    private static final String ACTION_SET_ENABLED_ALLOWED_RESOURCE = "setEnabledAllowedResource";

    private static final String VIEW_STATUS = "status";

    // AJAX Spider only views, not implemented, kept as no-ops for compatibility.
    private static final String VIEW_ALLOWED_RESOURCES = "allowedResources";
    private static final String VIEW_EXCLUDED_ELEMENTS = "excludedElements";
    private static final String VIEW_RESULTS = "results";
    private static final String VIEW_FULL_RESULTS = "fullResults";
    private static final String VIEW_NUMBER_OF_RESULTS = "numberOfResults";

    private static final String PARAM_CONTEXT_NAME = "contextName";
    private static final String PARAM_URL = "url";
    private static final String PARAM_USER_NAME = "userName";
    private static final String PARAM_IN_SCOPE = "inScope";
    private static final String PARAM_SUBTREE_ONLY = "subtreeOnly";

    private static final String PARAM_REGEX = "regex";
    private static final String PARAM_ENABLED = "enabled";
    private static final String PARAM_DESCRIPTION = "description";
    private static final String PARAM_DESCRIPTION_NEW = "descriptionNew";
    private static final String PARAM_ELEMENT = "element";
    private static final String PARAM_XPATH = "xpath";
    private static final String PARAM_TEXT = "text";
    private static final String PARAM_ATTRIBUTE_NAME = "attributeName";
    private static final String PARAM_ATTRIBUTE_VALUE = "attributeValue";
    private static final String PARAM_START = "start";
    private static final String PARAM_COUNT = "count";

    // clientSpider API param/value names, used only when delegating.
    private static final String PARAM_SCAN_ID = "scanId";
    private static final String PARAM_SCOPE_CHECK = "scopeCheck";
    private static final String SCOPE_CHECK_STRICT = "STRICT";

    private static final String CLIENT_SPIDER_PREFIX = "clientSpider";

    private static final String PARAM_INTEGER = "Integer";
    private static final String PARAM_BOOLEAN = "Boolean";
    private static final String PARAM_STRING = "String";

    // Real AJAX Spider option names, mapped onto the Client Spider's own options where possible.
    private static final String OPTION_NUMBER_OF_BROWSERS = "NumberOfBrowsers";
    private static final String OPTION_MAX_CRAWL_DEPTH = "MaxCrawlDepth";
    private static final String OPTION_MAX_DURATION = "MaxDuration";
    private static final String OPTION_BROWSER_ID = "BrowserId";
    private static final String OPTION_SCOPE_CHECK = "ScopeCheck";
    private static final String OPTION_LOGOUT_AVOIDANCE = "LogoutAvoidance";

    // Real AJAX Spider only options, no Client Spider equivalent - stored but otherwise no-ops.
    private static final String OPTION_MAX_CRAWL_STATES = "MaxCrawlStates";
    private static final String OPTION_EVENT_WAIT = "EventWait";
    private static final String OPTION_RELOAD_WAIT = "ReloadWait";
    private static final String OPTION_CLICK_DEFAULT_ELEMS = "ClickDefaultElems";
    private static final String OPTION_CLICK_ELEMS_ONCE = "ClickElemsOnce";
    private static final String OPTION_RANDOM_INPUTS = "RandomInputs";
    private static final String OPTION_ENABLE_EXTENSIONS = "EnableExtensions";

    // Action/view names for the options above (constant folded, usable as switch labels).
    private static final String ACTION_SET_OPTION_NUMBER_OF_BROWSERS =
            "setOption" + OPTION_NUMBER_OF_BROWSERS;
    private static final String ACTION_SET_OPTION_MAX_CRAWL_DEPTH =
            "setOption" + OPTION_MAX_CRAWL_DEPTH;
    private static final String ACTION_SET_OPTION_MAX_DURATION = "setOption" + OPTION_MAX_DURATION;
    private static final String ACTION_SET_OPTION_BROWSER_ID = "setOption" + OPTION_BROWSER_ID;
    private static final String ACTION_SET_OPTION_SCOPE_CHECK = "setOption" + OPTION_SCOPE_CHECK;
    private static final String ACTION_SET_OPTION_LOGOUT_AVOIDANCE =
            "setOption" + OPTION_LOGOUT_AVOIDANCE;
    private static final String ACTION_SET_OPTION_MAX_CRAWL_STATES =
            "setOption" + OPTION_MAX_CRAWL_STATES;
    private static final String ACTION_SET_OPTION_EVENT_WAIT = "setOption" + OPTION_EVENT_WAIT;
    private static final String ACTION_SET_OPTION_RELOAD_WAIT = "setOption" + OPTION_RELOAD_WAIT;
    private static final String ACTION_SET_OPTION_CLICK_DEFAULT_ELEMS =
            "setOption" + OPTION_CLICK_DEFAULT_ELEMS;
    private static final String ACTION_SET_OPTION_CLICK_ELEMS_ONCE =
            "setOption" + OPTION_CLICK_ELEMS_ONCE;
    private static final String ACTION_SET_OPTION_RANDOM_INPUTS =
            "setOption" + OPTION_RANDOM_INPUTS;
    private static final String ACTION_SET_OPTION_ENABLE_EXTENSIONS =
            "setOption" + OPTION_ENABLE_EXTENSIONS;

    private static final String VIEW_OPTION_NUMBER_OF_BROWSERS =
            "option" + OPTION_NUMBER_OF_BROWSERS;
    private static final String VIEW_OPTION_MAX_CRAWL_DEPTH = "option" + OPTION_MAX_CRAWL_DEPTH;
    private static final String VIEW_OPTION_MAX_DURATION = "option" + OPTION_MAX_DURATION;
    private static final String VIEW_OPTION_BROWSER_ID = "option" + OPTION_BROWSER_ID;
    private static final String VIEW_OPTION_SCOPE_CHECK = "option" + OPTION_SCOPE_CHECK;
    private static final String VIEW_OPTION_LOGOUT_AVOIDANCE = "option" + OPTION_LOGOUT_AVOIDANCE;
    private static final String VIEW_OPTION_MAX_CRAWL_STATES = "option" + OPTION_MAX_CRAWL_STATES;
    private static final String VIEW_OPTION_EVENT_WAIT = "option" + OPTION_EVENT_WAIT;
    private static final String VIEW_OPTION_RELOAD_WAIT = "option" + OPTION_RELOAD_WAIT;
    private static final String VIEW_OPTION_CLICK_DEFAULT_ELEMS =
            "option" + OPTION_CLICK_DEFAULT_ELEMS;
    private static final String VIEW_OPTION_CLICK_ELEMS_ONCE = "option" + OPTION_CLICK_ELEMS_ONCE;
    private static final String VIEW_OPTION_RANDOM_INPUTS = "option" + OPTION_RANDOM_INPUTS;
    private static final String VIEW_OPTION_ENABLE_EXTENSIONS = "option" + OPTION_ENABLE_EXTENSIONS;

    private enum SpiderStatus {
        STOPPED,
        RUNNING;

        @Override
        public String toString() {
            return super.toString().toLowerCase();
        }
    }

    private int currentScanId = -1;

    // Real AJAX Spider only option values, no Client Spider equivalent - stored but otherwise
    // no-ops.
    private int maxCrawlStates = 0;
    private int eventWait = 1000;
    private int reloadWait = 1000;
    private boolean clickDefaultElems = true;
    private boolean clickElemsOnce = true;
    private boolean randomInputs = true;
    private boolean enableExtensions = true;

    public AjaxSpiderAPI() {
        this.addApiAction(
                new ApiAction(
                        ACTION_START_SCAN,
                        null,
                        new String[] {
                            PARAM_URL, PARAM_IN_SCOPE, PARAM_CONTEXT_NAME, PARAM_SUBTREE_ONLY
                        }));
        this.addApiAction(
                new ApiAction(
                        ACTION_START_SCAN_AS_USER,
                        new String[] {PARAM_CONTEXT_NAME, PARAM_USER_NAME},
                        new String[] {PARAM_URL, PARAM_SUBTREE_ONLY}));
        this.addApiAction(new ApiAction(ACTION_STOP_SCAN));

        this.addApiAction(
                new ApiAction(
                        ACTION_ADD_ALLOWED_RESOURCE,
                        new String[] {PARAM_REGEX},
                        new String[] {PARAM_ENABLED}));
        this.addApiAction(
                new ApiAction(
                        ACTION_ADD_EXCLUDED_ELEMENT,
                        new String[] {PARAM_CONTEXT_NAME, PARAM_DESCRIPTION, PARAM_ELEMENT},
                        new String[] {
                            PARAM_XPATH,
                            PARAM_TEXT,
                            PARAM_ATTRIBUTE_NAME,
                            PARAM_ATTRIBUTE_VALUE,
                            PARAM_ENABLED
                        }));
        this.addApiAction(
                new ApiAction(
                        ACTION_MODIFY_EXCLUDED_ELEMENT,
                        new String[] {PARAM_CONTEXT_NAME, PARAM_DESCRIPTION, PARAM_ELEMENT},
                        new String[] {
                            PARAM_DESCRIPTION_NEW,
                            PARAM_XPATH,
                            PARAM_TEXT,
                            PARAM_ATTRIBUTE_NAME,
                            PARAM_ATTRIBUTE_VALUE,
                            PARAM_ENABLED
                        }));
        this.addApiAction(
                new ApiAction(
                        ACTION_REMOVE_EXCLUDED_ELEMENT,
                        new String[] {PARAM_CONTEXT_NAME, PARAM_DESCRIPTION}));
        this.addApiAction(
                new ApiAction(ACTION_REMOVE_ALLOWED_RESOURCE, new String[] {PARAM_REGEX}));
        this.addApiAction(
                new ApiAction(
                        ACTION_SET_ENABLED_ALLOWED_RESOURCE,
                        new String[] {PARAM_REGEX, PARAM_ENABLED}));

        this.addApiView(new ApiView(VIEW_STATUS));

        this.addApiView(new ApiView(VIEW_ALLOWED_RESOURCES));
        this.addApiView(
                new ApiView(VIEW_EXCLUDED_ELEMENTS, null, new String[] {PARAM_CONTEXT_NAME}));
        this.addApiView(new ApiView(VIEW_RESULTS, null, new String[] {PARAM_START, PARAM_COUNT}));
        this.addApiView(new ApiView(VIEW_NUMBER_OF_RESULTS));
        this.addApiView(new ApiView(VIEW_FULL_RESULTS));

        addIntOption(OPTION_NUMBER_OF_BROWSERS);
        addIntOption(OPTION_MAX_CRAWL_DEPTH);
        addIntOption(OPTION_MAX_CRAWL_STATES);
        addIntOption(OPTION_MAX_DURATION);
        addIntOption(OPTION_EVENT_WAIT);
        addIntOption(OPTION_RELOAD_WAIT);
        addStringOption(OPTION_BROWSER_ID);
        addBooleanOption(OPTION_CLICK_DEFAULT_ELEMS);
        addBooleanOption(OPTION_CLICK_ELEMS_ONCE);
        addBooleanOption(OPTION_RANDOM_INPUTS);
        addBooleanOption(OPTION_ENABLE_EXTENSIONS);
        addStringOption(OPTION_SCOPE_CHECK);
        addBooleanOption(OPTION_LOGOUT_AVOIDANCE);
    }

    private void addIntOption(String name) {
        this.addApiAction(new ApiAction("setOption" + name, new String[] {PARAM_INTEGER}));
        this.addApiView(new ApiView("option" + name));
    }

    private void addBooleanOption(String name) {
        this.addApiAction(new ApiAction("setOption" + name, new String[] {PARAM_BOOLEAN}));
        this.addApiView(new ApiView("option" + name));
    }

    private void addStringOption(String name) {
        this.addApiAction(new ApiAction("setOption" + name, new String[] {PARAM_STRING}));
        this.addApiView(new ApiView("option" + name));
    }

    @Override
    public String getPrefix() {
        return PREFIX;
    }

    @Override
    protected String getI18nPrefix() {
        return "client.ajaxSpider";
    }

    /**
     * Gets the real {@code clientSpider} API implementor, to which requests are delegated.
     *
     * @throws ApiException if the {@code clientSpider} API is not registered.
     */
    private static ApiImplementor getClientSpiderImplementor() throws ApiException {
        ApiImplementor impl = API.getInstance().getImplementors().get(CLIENT_SPIDER_PREFIX);
        if (impl == null) {
            throw new ApiException(ApiException.Type.INTERNAL_ERROR, CLIENT_SPIDER_PREFIX);
        }
        return impl;
    }

    /**
     * Translates the given ajaxSpider {@code scan}/{@code scanAsUser} params into clientSpider ones
     * (only {@code inScope} needs translating, into {@code scopeCheck}) and delegates to the real
     * clientSpider {@code scan} action, tracking the returned scan ID.
     *
     * @param params the ajaxSpider action params ({@code url}, {@code contextName}, {@code
     *     userName}, {@code inScope}, {@code subtreeOnly} - all optional).
     */
    private ApiResponse delegateStartScan(JSONObject params) throws ApiException {
        if (isSpiderRunning()) {
            throw new ApiException(ApiException.Type.SCAN_IN_PROGRESS);
        }

        JSONObject clientParams = JSONObject.fromObject(params);
        clientParams.remove(PARAM_IN_SCOPE);
        if (getParam(params, PARAM_IN_SCOPE, false)) {
            clientParams.put(PARAM_SCOPE_CHECK, SCOPE_CHECK_STRICT);
        }

        ApiResponseElement response =
                (ApiResponseElement)
                        getClientSpiderImplementor()
                                .handleApiAction(ACTION_START_SCAN, clientParams);
        currentScanId = Integer.parseInt(response.getValue());
        return ApiResponseElement.OK;
    }

    /**
     * Stops the scan started via this API (if any), by delegating to the real clientSpider {@code
     * stop} action.
     */
    private void delegateStopScan() throws ApiException {
        if (currentScanId == -1) {
            return;
        }
        JSONObject clientParams = new JSONObject();
        clientParams.put(PARAM_SCAN_ID, currentScanId);
        getClientSpiderImplementor().handleApiAction(ACTION_STOP_SCAN, clientParams);
    }

    @Override
    public ApiResponse handleApiAction(String name, JSONObject params) throws ApiException {
        switch (name) {
            case ACTION_START_SCAN:
            case ACTION_START_SCAN_AS_USER:
                return delegateStartScan(params);

            case ACTION_STOP_SCAN:
                delegateStopScan();
                break;

            case ACTION_ADD_ALLOWED_RESOURCE:
            case ACTION_ADD_EXCLUDED_ELEMENT:
            case ACTION_MODIFY_EXCLUDED_ELEMENT:
            case ACTION_REMOVE_ALLOWED_RESOURCE:
            case ACTION_REMOVE_EXCLUDED_ELEMENT:
            case ACTION_SET_ENABLED_ALLOWED_RESOURCE:
                // AJAX Spider only actions, no Client Spider equivalent - no-op.
                break;

            case ACTION_SET_OPTION_NUMBER_OF_BROWSERS:
                return delegateSetOption("ThreadCount", PARAM_INTEGER, params);
            case ACTION_SET_OPTION_MAX_CRAWL_DEPTH:
                return delegateSetOption("MaxDepth", PARAM_INTEGER, params);
            case ACTION_SET_OPTION_MAX_DURATION:
                return delegateSetOption("MaxDuration", PARAM_INTEGER, params);
            case ACTION_SET_OPTION_BROWSER_ID:
                return delegateSetOption("BrowserId", PARAM_STRING, params);
            case ACTION_SET_OPTION_SCOPE_CHECK:
                return delegateSetOption("ScopeCheck", PARAM_STRING, params);
            case ACTION_SET_OPTION_LOGOUT_AVOIDANCE:
                return delegateSetOption("LogoutAvoidance", PARAM_BOOLEAN, params);

            case ACTION_SET_OPTION_MAX_CRAWL_STATES:
                // AJAX Spider only option, no Client Spider equivalent - no-op.
                maxCrawlStates = params.getInt(PARAM_INTEGER);
                break;
            case ACTION_SET_OPTION_EVENT_WAIT:
                // AJAX Spider only option, no Client Spider equivalent - no-op.
                eventWait = params.getInt(PARAM_INTEGER);
                break;
            case ACTION_SET_OPTION_RELOAD_WAIT:
                // AJAX Spider only option, no Client Spider equivalent - no-op.
                reloadWait = params.getInt(PARAM_INTEGER);
                break;
            case ACTION_SET_OPTION_CLICK_DEFAULT_ELEMS:
                // AJAX Spider only option, no Client Spider equivalent - no-op.
                clickDefaultElems = params.getBoolean(PARAM_BOOLEAN);
                break;
            case ACTION_SET_OPTION_CLICK_ELEMS_ONCE:
                // AJAX Spider only option, no Client Spider equivalent - no-op.
                clickElemsOnce = params.getBoolean(PARAM_BOOLEAN);
                break;
            case ACTION_SET_OPTION_RANDOM_INPUTS:
                // AJAX Spider only option, no Client Spider equivalent - no-op.
                randomInputs = params.getBoolean(PARAM_BOOLEAN);
                break;
            case ACTION_SET_OPTION_ENABLE_EXTENSIONS:
                // AJAX Spider only option, no Client Spider equivalent - no-op.
                enableExtensions = params.getBoolean(PARAM_BOOLEAN);
                break;

            default:
                throw new ApiException(ApiException.Type.BAD_ACTION);
        }
        return ApiResponseElement.OK;
    }

    /**
     * Delegates a {@code setOptionX} action to the equivalent real clientSpider option, forwarding
     * the single supplied param value unchanged.
     *
     * @param clientOptionSuffix the clientSpider option name suffix (e.g. {@code "MaxDepth"}).
     * @param paramName the param name/type ({@link #PARAM_INTEGER}, {@link #PARAM_BOOLEAN} or
     *     {@link #PARAM_STRING}) used by both the ajaxSpider and clientSpider option actions.
     */
    private static ApiResponse delegateSetOption(
            String clientOptionSuffix, String paramName, JSONObject params) throws ApiException {
        JSONObject clientParams = new JSONObject();
        clientParams.put(paramName, params.get(paramName));
        ApiResponse response =
                getClientSpiderImplementor()
                        .handleApiOptionAction("setOption" + clientOptionSuffix, clientParams);
        if (response == null) {
            throw new ApiException(ApiException.Type.INTERNAL_ERROR, clientOptionSuffix);
        }
        return response;
    }

    /**
     * Delegates an {@code optionX} view to the equivalent real clientSpider option, returning the
     * value under the ajaxSpider view's own name.
     *
     * @param name the ajaxSpider view name (e.g. {@code "optionNumberOfBrowsers"}).
     * @param clientOptionSuffix the clientSpider option name suffix (e.g. {@code "ThreadCount"}).
     */
    private static ApiResponse delegateGetOption(String name, String clientOptionSuffix)
            throws ApiException {
        ApiResponse response =
                getClientSpiderImplementor()
                        .handleApiOptionView("option" + clientOptionSuffix, new JSONObject());
        if (response == null) {
            throw new ApiException(ApiException.Type.INTERNAL_ERROR, clientOptionSuffix);
        }
        return new ApiResponseElement(name, ((ApiResponseElement) response).getValue());
    }

    @Override
    public ApiResponse handleApiView(String name, JSONObject params) throws ApiException {
        switch (name) {
            case VIEW_STATUS:
                return new ApiResponseElement(
                        name,
                        isSpiderRunning()
                                ? SpiderStatus.RUNNING.toString()
                                : SpiderStatus.STOPPED.toString());

            case VIEW_ALLOWED_RESOURCES:
            case VIEW_EXCLUDED_ELEMENTS:
            case VIEW_RESULTS:
                // AJAX Spider only views, no Client Spider equivalent - always empty.
                return new ApiResponseList(name);

            case VIEW_FULL_RESULTS:
                // AJAX Spider only view, no Client Spider equivalent - always empty, but same
                // {inScope, outOfScope, errors} shape as the real endpoint for compatibility.
                return new EmptyFullResultsApiResponse(name);

            case VIEW_NUMBER_OF_RESULTS:
                // AJAX Spider only view, no Client Spider equivalent - always zero.
                return new ApiResponseElement(name, "0");

            case VIEW_OPTION_NUMBER_OF_BROWSERS:
                return delegateGetOption(name, "ThreadCount");
            case VIEW_OPTION_MAX_CRAWL_DEPTH:
                return delegateGetOption(name, "MaxDepth");
            case VIEW_OPTION_MAX_DURATION:
                return delegateGetOption(name, "MaxDuration");
            case VIEW_OPTION_BROWSER_ID:
                return delegateGetOption(name, "BrowserId");
            case VIEW_OPTION_SCOPE_CHECK:
                return delegateGetOption(name, "ScopeCheck");
            case VIEW_OPTION_LOGOUT_AVOIDANCE:
                return delegateGetOption(name, "LogoutAvoidance");

            case VIEW_OPTION_MAX_CRAWL_STATES:
                // AJAX Spider only option, no Client Spider equivalent - no-op.
                return new ApiResponseElement(name, String.valueOf(maxCrawlStates));
            case VIEW_OPTION_EVENT_WAIT:
                // AJAX Spider only option, no Client Spider equivalent - no-op.
                return new ApiResponseElement(name, String.valueOf(eventWait));
            case VIEW_OPTION_RELOAD_WAIT:
                // AJAX Spider only option, no Client Spider equivalent - no-op.
                return new ApiResponseElement(name, String.valueOf(reloadWait));
            case VIEW_OPTION_CLICK_DEFAULT_ELEMS:
                // AJAX Spider only option, no Client Spider equivalent - no-op.
                return new ApiResponseElement(name, String.valueOf(clickDefaultElems));
            case VIEW_OPTION_CLICK_ELEMS_ONCE:
                // AJAX Spider only option, no Client Spider equivalent - no-op.
                return new ApiResponseElement(name, String.valueOf(clickElemsOnce));
            case VIEW_OPTION_RANDOM_INPUTS:
                // AJAX Spider only option, no Client Spider equivalent - no-op.
                return new ApiResponseElement(name, String.valueOf(randomInputs));
            case VIEW_OPTION_ENABLE_EXTENSIONS:
                // AJAX Spider only option, no Client Spider equivalent - no-op.
                return new ApiResponseElement(name, String.valueOf(enableExtensions));

            default:
                throw new ApiException(ApiException.Type.BAD_VIEW);
        }
    }

    /**
     * Tells whether the scan started via this API (if any) is still running, by delegating to the
     * real clientSpider {@code status} view.
     */
    private boolean isSpiderRunning() throws ApiException {
        if (currentScanId == -1) {
            return false;
        }
        JSONObject clientParams = new JSONObject();
        clientParams.put(PARAM_SCAN_ID, currentScanId);
        ApiResponseElement response =
                (ApiResponseElement)
                        getClientSpiderImplementor().handleApiView(VIEW_STATUS, clientParams);
        return Integer.parseInt(response.getValue()) < 100;
    }

    /**
     * Stops the scan started via this API (if any). Errors are logged rather than thrown, since
     * this is a best-effort cleanup (e.g. called when handing the API prefix back to the real AJAX
     * Spider add-on).
     */
    void stopSpider() {
        try {
            delegateStopScan();
        } catch (ApiException e) {
            LOGGER.warn("Failed to stop the Client Spider scan: {}", e.getMessage(), e);
        }
    }

    /**
     * Always-empty {@code fullResults} response, matching the {@code inScope}/{@code
     * outOfScope}/{@code errors} object shape of the real (unimplemented) endpoint, for
     * compatibility with existing clients.
     */
    private static class EmptyFullResultsApiResponse extends ApiResponse {

        private final ApiResponseList inScope = new ApiResponseList("inScope");
        private final ApiResponseList outOfScope = new ApiResponseList("outOfScope");
        private final ApiResponseList errors = new ApiResponseList("errors");

        EmptyFullResultsApiResponse(String name) {
            super(name);
        }

        @Override
        public void toXML(Document doc, Element parent) {
            parent.setAttribute("type", "set");

            Element el = doc.createElement(inScope.getName());
            inScope.toXML(doc, el);
            parent.appendChild(el);

            el = doc.createElement(outOfScope.getName());
            outOfScope.toXML(doc, el);
            parent.appendChild(el);

            el = doc.createElement(errors.getName());
            errors.toXML(doc, el);
            parent.appendChild(el);
        }

        @Override
        public JSON toJSON() {
            JSONObject scopes = new JSONObject();
            scopes.put(inScope.getName(), ((JSONObject) inScope.toJSON()).get(inScope.getName()));
            scopes.put(
                    outOfScope.getName(),
                    ((JSONObject) outOfScope.toJSON()).get(outOfScope.getName()));
            scopes.put(errors.getName(), ((JSONObject) errors.toJSON()).get(errors.getName()));

            JSONObject jo = new JSONObject();
            jo.put(getName(), scopes);
            return jo;
        }

        @Override
        public void toHTML(StringBuilder sb) {
            sb.append("<h2>" + this.getName() + "</h2>\n");
            inScope.toHTML(sb);
            outOfScope.toHTML(sb);
            errors.toHTML(sb);
        }

        @Override
        public String toString(int indent) {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < indent; i++) {
                sb.append("\t");
            }
            sb.append("ApiResponseSet ");
            sb.append(this.getName());
            sb.append(" : [\n");
            sb.append(inScope.toString(indent + 1));
            sb.append(outOfScope.toString(indent + 1));
            sb.append(errors.toString(indent + 1));
            for (int i = 0; i < indent; i++) {
                sb.append("\t");
            }
            sb.append("]\n");
            return sb.toString();
        }
    }
}
