/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2015 The ZAP Development Team
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
package org.zaproxy.zap.extension.selenium;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import net.sf.json.JSONObject;
import org.zaproxy.zap.extension.api.ApiAction;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.extension.api.ApiException.Type;
import org.zaproxy.zap.extension.api.ApiImplementor;
import org.zaproxy.zap.extension.api.ApiResponse;
import org.zaproxy.zap.extension.api.ApiResponseElement;
import org.zaproxy.zap.extension.api.ApiResponseList;
import org.zaproxy.zap.extension.api.ApiResponseSet;
import org.zaproxy.zap.extension.api.ApiView;
import org.zaproxy.zap.extension.selenium.internal.BrowserArgument;

/** The Selenium API. */
public class SeleniumAPI extends ApiImplementor {

    private static final String API_PREFIX = "selenium";

    private static final String ACTION_ADD_BROWSER_ARGUMENT = "addBrowserArgument";
    private static final String ACTION_REMOVE_BROWSER_ARGUMENT = "removeBrowserArgument";
    private static final String ACTION_SET_BROWSER_ARGUMENT_ENABLED = "setBrowserArgumentEnabled";

    private static final String VIEW_GET_BROWSER_ARGUMENTS = "getBrowserArguments";

    private static final String PARAM_BROWSER = "browser";
    private static final String PARAM_ENABLED = "enabled";
    private static final String PARAM_ARGUMENT = "argument";

    private final SeleniumOptions options;

    /** Provided only for API client generator usage. */
    public SeleniumAPI() {
        this(new SeleniumOptions());
    }

    /**
     * Constructs a {@code SeleniumAPI} with the given {@code options} exposed through the API.
     *
     * @param options the options that will be exposed through the API
     */
    public SeleniumAPI(SeleniumOptions options) {
        this.options = options;
        addApiOptions(options);

        addApiAction(
                new ApiAction(
                        ACTION_ADD_BROWSER_ARGUMENT,
                        List.of(PARAM_BROWSER, PARAM_ARGUMENT),
                        List.of(PARAM_ENABLED)));
        addApiAction(
                new ApiAction(
                        ACTION_REMOVE_BROWSER_ARGUMENT, List.of(PARAM_BROWSER, PARAM_ARGUMENT)));
        addApiAction(
                new ApiAction(
                        ACTION_SET_BROWSER_ARGUMENT_ENABLED,
                        List.of(PARAM_BROWSER, PARAM_ARGUMENT, PARAM_ENABLED)));

        addApiView(new ApiView(VIEW_GET_BROWSER_ARGUMENTS, List.of(PARAM_BROWSER)));
    }

    @Override
    public String getPrefix() {
        return API_PREFIX;
    }

    @Override
    public ApiResponse handleApiAction(String name, JSONObject params) throws ApiException {
        switch (name) {
            case ACTION_ADD_BROWSER_ARGUMENT:
                {
                    String browser = getBrowser(params);
                    String argument = params.getString(PARAM_ARGUMENT);
                    boolean enabled = getParam(params, PARAM_ENABLED, true);
                    BrowserArgument browserArgument = new BrowserArgument(argument, enabled);
                    options.addBrowserArgument(browser, browserArgument);
                    return ApiResponseElement.OK;
                }

            case ACTION_REMOVE_BROWSER_ARGUMENT:
                {
                    String browser = getBrowser(params);
                    String argument = params.getString(PARAM_ARGUMENT);
                    boolean removed = options.removeBrowserArgument(browser, argument);
                    if (!removed) {
                        throw new ApiException(ApiException.Type.DOES_NOT_EXIST, PARAM_ARGUMENT);
                    }
                    return ApiResponseElement.OK;
                }

            case ACTION_SET_BROWSER_ARGUMENT_ENABLED:
                {
                    String browser = getBrowser(params);
                    String argument = params.getString(PARAM_ARGUMENT);
                    boolean enabled = getParam(params, PARAM_ENABLED, true);
                    boolean changed = options.setBrowserArgumentEnabled(browser, argument, enabled);
                    if (!changed) {
                        throw new ApiException(ApiException.Type.DOES_NOT_EXIST, PARAM_ARGUMENT);
                    }
                    return ApiResponseElement.OK;
                }

            default:
                throw new ApiException(ApiException.Type.BAD_ACTION);
        }
    }

    @Override
    public ApiResponse handleApiView(String name, JSONObject params) throws ApiException {
        switch (name) {
            case VIEW_GET_BROWSER_ARGUMENTS:
                {
                    ApiResponseList response = new ApiResponseList(name);
                    String browser = getBrowser(params);
                    for (BrowserArgument browserArgument : options.getBrowserArguments(browser)) {
                        Map<String, Object> entry = new HashMap<>();
                        entry.put("argument", browserArgument.getArgument());
                        entry.put("enabled", browserArgument.isEnabled());
                        response.addItem(new ApiResponseSet<>("arg", entry));
                    }
                    return response;
                }

            default:
                throw new ApiException(ApiException.Type.BAD_VIEW);
        }
    }

    private static String getBrowser(JSONObject params) throws ApiException {
        String browser = params.getString(PARAM_BROWSER);
        if (!(Browser.CHROME.getId().equals(browser) || Browser.FIREFOX.getId().equals(browser))) {
            throw new ApiException(Type.ILLEGAL_PARAMETER, PARAM_BROWSER);
        }
        return browser;
    }
}
