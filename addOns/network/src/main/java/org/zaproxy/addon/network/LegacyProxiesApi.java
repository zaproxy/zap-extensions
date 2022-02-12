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
package org.zaproxy.addon.network;

import java.util.HashMap;
import java.util.Map;
import net.sf.json.JSONObject;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.network.internal.server.http.LocalServerConfig;
import org.zaproxy.zap.extension.api.API;
import org.zaproxy.zap.extension.api.ApiAction;
import org.zaproxy.zap.extension.api.ApiElement;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.extension.api.ApiImplementor;
import org.zaproxy.zap.extension.api.ApiResponse;
import org.zaproxy.zap.extension.api.ApiResponseElement;
import org.zaproxy.zap.extension.api.ApiResponseList;
import org.zaproxy.zap.extension.api.ApiResponseSet;
import org.zaproxy.zap.extension.api.ApiView;

class LegacyProxiesApi extends ApiImplementor {

    private static final String PREFIX = "localProxies";

    private static final String VIEW_ADDITIONAL_PROXIES = "additionalProxies";
    private static final String ACTION_ADD_PROXY = "addAdditionalProxy";
    private static final String ACTION_REMOVE_PROXY = "removeAdditionalProxy";
    private static final String PARAM_ADDRESS = "address";
    private static final String PARAM_PORT = "port";
    private static final String PARAM_BEHIND_NAT = "behindNat";
    private static final String PARAM_DECODE_ZIP = "alwaysDecodeZip";
    private static final String PARAM_REM_UNSUPPORTED_ENC = "removeUnsupportedEncodings";

    private final ExtensionNetwork extensionNetwork;

    public LegacyProxiesApi(ExtensionNetwork extensionNetwork) {
        this.extensionNetwork = extensionNetwork;

        this.addApiView(deprecate(new ApiView(VIEW_ADDITIONAL_PROXIES)));
        this.addApiAction(
                deprecate(
                        new ApiAction(
                                ACTION_ADD_PROXY,
                                new String[] {PARAM_ADDRESS, PARAM_PORT},
                                new String[] {
                                    PARAM_BEHIND_NAT, PARAM_DECODE_ZIP, PARAM_REM_UNSUPPORTED_ENC
                                })));
        this.addApiAction(
                deprecate(
                        new ApiAction(
                                ACTION_REMOVE_PROXY, new String[] {PARAM_ADDRESS, PARAM_PORT})));
    }

    private static <T extends ApiElement> T deprecate(T element) {
        element.setDeprecated(true);
        element.setDeprecatedDescription(
                Constant.messages.getString("network.api.legacy.deprecated.network"));
        return element;
    }

    @Override
    protected String getI18nPrefix() {
        return "network.api.legacy";
    }

    @Override
    public String getPrefix() {
        return PREFIX;
    }

    @Override
    public ApiResponse handleApiView(String name, JSONObject params) throws ApiException {
        if (VIEW_ADDITIONAL_PROXIES.equals(name)) {
            ApiResponseList response = new ApiResponseList(name);

            for (LocalServerConfig p : extensionNetwork.getLocalServersOptions().getServers()) {
                Map<String, String> map = new HashMap<>();
                map.put("address", p.getAddress());
                map.put("port", Integer.toString(p.getPort()));
                map.put("enabled", Boolean.toString(p.isEnabled()));
                map.put("behindNat", Boolean.toString(p.isBehindNat()));
                map.put("alwaysDecodeZip", Boolean.toString(p.isDecodeResponse()));
                map.put("removeUnsupportedEncodings", Boolean.toString(p.isRemoveAcceptEncoding()));
                response.addItem(new ApiResponseSet<>("proxy", map));
            }

            return response;
        }

        throw new ApiException(ApiException.Type.BAD_VIEW, name);
    }

    @Override
    public ApiResponse handleApiAction(String name, JSONObject params) throws ApiException {
        if (ACTION_ADD_PROXY.equals(name)) {
            params.put(
                    "removeAcceptEncoding", params.optString(PARAM_REM_UNSUPPORTED_ENC, "false"));
            params.put("decodeResponse", params.optString(PARAM_DECODE_ZIP, "false"));
            getNetworkImplementor().handleApiAction("addLocalServer", params);
            return ApiResponseElement.OK;
        }

        if (ACTION_REMOVE_PROXY.equals(name)) {
            try {
                getNetworkImplementor().handleApiAction("removeLocalServer", params);
                return ApiResponseElement.OK;
            } catch (ApiException e) {
                String address = params.getString(PARAM_ADDRESS);
                int port = params.getInt(PARAM_PORT);
                throw new ApiException(
                        ApiException.Type.ILLEGAL_PARAMETER,
                        "Proxy not found: " + address + ":" + port);
            }
        }

        throw new ApiException(ApiException.Type.BAD_ACTION, name);
    }

    private static ApiImplementor getNetworkImplementor() {
        return API.getInstance().getImplementors().get("network");
    }
}
