/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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
package org.zaproxy.addon.oast;

import java.util.HashMap;
import net.sf.json.JSONObject;
import org.zaproxy.zap.extension.api.ApiAction;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.extension.api.ApiImplementor;
import org.zaproxy.zap.extension.api.ApiResponse;
import org.zaproxy.zap.extension.api.ApiResponseElement;
import org.zaproxy.zap.extension.api.ApiResponseList;
import org.zaproxy.zap.extension.api.ApiResponseSet;
import org.zaproxy.zap.extension.api.ApiView;
import org.zaproxy.zap.utils.ApiUtils;

public class OastApi extends ApiImplementor {
    private static final String PREFIX = "oast";

    private static final String ACTION_SET_ACTIVE_SCAN_SERVICE = "setActiveScanService";
    private static final String ACTION_SET_DAYS_TO_KEEP_RECORDS = "setDaysToKeepRecords";
    private static final String ACTION_SET_BOAST_OPTIONS = "setBoastOptions";
    private static final String ACTION_SET_CALLBACK_OPTIONS = "setCallbackOptions";
    private static final String ACTION_SET_INTERACTSH_OPTIONS = "setInteractshOptions";

    private static final String VIEW_GET_ACTIVE_SCAN_SERVICE = "getActiveScanService";
    private static final String VIEW_GET_SERVICES = "getServices";
    private static final String VIEW_GET_DAYS_TO_KEEP_RECORDS = "getDaysToKeepRecords";
    private static final String VIEW_GET_BOAST_OPTIONS = "getBoastOptions";
    private static final String VIEW_GET_CALLBACK_OPTIONS = "getCallbackOptions";
    private static final String VIEW_GET_INTERACTSH_OPTIONS = "getInteractshOptions";

    private static final String PARAM_AUTH_TOKEN = "authToken";
    private static final String PARAM_NAME = "name";
    private static final String PARAM_LOCAL_ADDR = "localAddress";
    private static final String PARAM_REMOTE_ADDR = "remoteAddress";
    private static final String PARAM_SERVER = "server";
    private static final String PARAM_POLL_IN_SECS = "pollInSecs";
    private static final String PARAM_PORT = "port";
    private static final String PARAM_DAYS = "days";

    private ExtensionOast ext;

    /*
     * Constructor should just be used for API generation.
     */
    public OastApi() {
        this(null);
    }

    public OastApi(ExtensionOast ext) {
        this.ext = ext;
        this.addApiView(new ApiView(VIEW_GET_ACTIVE_SCAN_SERVICE));
        this.addApiView(new ApiView(VIEW_GET_SERVICES));
        this.addApiView(new ApiView(VIEW_GET_BOAST_OPTIONS));
        this.addApiView(new ApiView(VIEW_GET_CALLBACK_OPTIONS));
        this.addApiView(new ApiView(VIEW_GET_INTERACTSH_OPTIONS));
        this.addApiView(new ApiView(VIEW_GET_DAYS_TO_KEEP_RECORDS));

        this.addApiAction(new ApiAction(ACTION_SET_ACTIVE_SCAN_SERVICE, new String[] {PARAM_NAME}));
        this.addApiAction(
                new ApiAction(
                        ACTION_SET_BOAST_OPTIONS, new String[] {PARAM_SERVER, PARAM_POLL_IN_SECS}));
        this.addApiAction(
                new ApiAction(
                        ACTION_SET_CALLBACK_OPTIONS,
                        new String[] {PARAM_LOCAL_ADDR, PARAM_REMOTE_ADDR, PARAM_PORT}));
        this.addApiAction(
                new ApiAction(
                        ACTION_SET_INTERACTSH_OPTIONS,
                        new String[] {PARAM_SERVER, PARAM_POLL_IN_SECS, PARAM_AUTH_TOKEN}));
        this.addApiAction(
                new ApiAction(ACTION_SET_DAYS_TO_KEEP_RECORDS, new String[] {PARAM_DAYS}));
    }

    @Override
    public String getPrefix() {
        return PREFIX;
    }

    @Override
    public ApiResponse handleApiAction(String name, JSONObject params) throws ApiException {
        switch (name) {
            case ACTION_SET_ACTIVE_SCAN_SERVICE:
                try {
                    ext.setActiveScanOastService(params.getString(PARAM_NAME));
                } catch (IllegalArgumentException e) {
                    throw new ApiException(
                            ApiException.Type.ILLEGAL_PARAMETER, params.getString(PARAM_NAME));
                }
                break;
            case ACTION_SET_DAYS_TO_KEEP_RECORDS:
                int days = ApiUtils.getIntParam(params, PARAM_DAYS);
                ext.getParams().setDaysToKeepRecords(days);
                ext.trimDatabase(days);
                break;

            case ACTION_SET_BOAST_OPTIONS:
                ext.getBoastService().getParam().setBoastUri(params.getString(PARAM_SERVER));
                ext.getBoastService()
                        .getParam()
                        .setPollingFrequency(ApiUtils.getIntParam(params, PARAM_POLL_IN_SECS));
                ext.getBoastService().optionsChanged(ext.getModel().getOptionsParam());
                break;
            case ACTION_SET_CALLBACK_OPTIONS:
                ext.getCallbackService()
                        .getParam()
                        .setLocalAddress(params.getString(PARAM_LOCAL_ADDR));
                ext.getCallbackService()
                        .getParam()
                        .setRemoteAddress(params.getString(PARAM_REMOTE_ADDR));
                ext.getCallbackService()
                        .getParam()
                        .setPort(ApiUtils.getIntParam(params, PARAM_PORT));
                ext.getCallbackService().optionsChanged(ext.getModel().getOptionsParam());
                break;
            case ACTION_SET_INTERACTSH_OPTIONS:
                ext.getInteractshService().getParam().setServerUrl(params.getString(PARAM_SERVER));
                ext.getInteractshService()
                        .getParam()
                        .setAuthToken(params.getString(PARAM_AUTH_TOKEN));
                ext.getInteractshService().optionsChanged(ext.getModel().getOptionsParam());
                ext.getInteractshService()
                        .getParam()
                        .setPollingFrequency(ApiUtils.getIntParam(params, PARAM_POLL_IN_SECS));
                break;
            default:
                throw new ApiException(ApiException.Type.BAD_ACTION);
        }

        return ApiResponseElement.OK;
    }

    @Override
    public ApiResponse handleApiView(String name, JSONObject params) throws ApiException {
        switch (name) {
            case VIEW_GET_ACTIVE_SCAN_SERVICE:
                OastService service = ext.getActiveScanOastService();
                return new ApiResponseElement(name, service != null ? service.getName() : "");
            case VIEW_GET_DAYS_TO_KEEP_RECORDS:
                return new ApiResponseElement(
                        name, Integer.toString(ext.getParams().getDaysToKeepRecords()));
            case VIEW_GET_SERVICES:
                ApiResponseList servList = new ApiResponseList(name);

                ext.getOastServices()
                        .forEach(
                                (sname, serv) ->
                                        servList.addItem(
                                                new ApiResponseElement(PARAM_NAME, sname)));
                return servList;
            case VIEW_GET_BOAST_OPTIONS:
                ApiResponseSet<String> boastOpts =
                        new ApiResponseSet<>(name, new HashMap<String, String>());
                boastOpts.put(PARAM_SERVER, ext.getBoastService().getParam().getBoastUri());
                boastOpts.put(
                        PARAM_POLL_IN_SECS,
                        Integer.toString(ext.getBoastService().getParam().getPollingFrequency()));
                return boastOpts;
            case VIEW_GET_CALLBACK_OPTIONS:
                ApiResponseSet<String> callbackOpts =
                        new ApiResponseSet<>(name, new HashMap<String, String>());
                callbackOpts.put(
                        PARAM_LOCAL_ADDR, ext.getCallbackService().getParam().getLocalAddress());
                callbackOpts.put(
                        PARAM_REMOTE_ADDR, ext.getCallbackService().getParam().getRemoteAddress());
                callbackOpts.put(
                        PARAM_PORT,
                        Integer.toString(ext.getCallbackService().getParam().getPort()));
                return callbackOpts;
            case VIEW_GET_INTERACTSH_OPTIONS:
                ApiResponseSet<String> interOpts =
                        new ApiResponseSet<>(name, new HashMap<String, String>());
                interOpts.put(PARAM_SERVER, ext.getInteractshService().getParam().getServerUrl());
                interOpts.put(
                        PARAM_AUTH_TOKEN, ext.getInteractshService().getParam().getAuthToken());
                interOpts.put(
                        PARAM_POLL_IN_SECS,
                        Integer.toString(
                                ext.getInteractshService().getParam().getPollingFrequency()));
                return interOpts;
            default:
                throw new ApiException(ApiException.Type.BAD_VIEW);
        }
    }
}
