/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 * 
 * Copyright 2017 The ZAP Development Team
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
package org.zaproxy.zap.extension.quickstart.launch;

import net.sf.json.JSONObject;

import org.parosproxy.paros.core.proxy.ProxyParam;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.api.API;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.extension.api.ApiImplementor;
import org.zaproxy.zap.extension.api.ApiOther;
import org.zaproxy.zap.extension.api.API.RequestType;
import org.zaproxy.zap.extension.api.OptionsParamApi;

/**
 * The Quick Start Launch API.
 */
public class QuickStartLaunchAPI extends ApiImplementor {

    protected static final String API_PREFIX = "quickstartlaunch";

    protected static final String OTHER_START_PAGE = "startPage";
    
    private ExtensionQuickStartLaunch ext;

    public QuickStartLaunchAPI(ExtensionQuickStartLaunch ext) {
        this.ext = ext;
        this.addApiOthers(new ApiOther(OTHER_START_PAGE));
    }

    @Override
    public String getPrefix() {
        return API_PREFIX;
    }

    private String getResponseHeader(String contentType, int contentLength, boolean canCache) {
        StringBuilder sb = new StringBuilder(250);

        sb.append("HTTP/1.1 200 OK\r\n");
        if (! canCache) {
            sb.append("Pragma: no-cache\r\n");
            sb.append("Cache-Control: no-cache\r\n");
        }
        sb.append("Content-Security-Policy: default-src 'none'; script-src 'none'; connect-src 'self'; child-src 'self'; img-src https://*; font-src 'self' data:; style-src 'self' 'unsafe-inline';\r\n");
        sb.append("Referrer-Policy: no-referrer\r\n");
        sb.append("Access-Control-Allow-Methods: GET,POST,OPTIONS\r\n");
        sb.append("Access-Control-Allow-Headers: ZAP-Header\r\n");
        sb.append("X-Frame-Options: DENY\r\n");
        sb.append("X-XSS-Protection: 1; mode=block\r\n");
        sb.append("X-Content-Type-Options: nosniff\r\n");
        sb.append("X-Clacks-Overhead: GNU Terry Pratchett\r\n");
        sb.append("Content-Length: ").append(contentLength).append("\r\n");
        sb.append("Content-Type: ").append(contentType).append("\r\n");

        return sb.toString();
    }

    @Override
    public HttpMessage handleApiOther(HttpMessage msg, String name, JSONObject params) throws ApiException {
        if (OTHER_START_PAGE.equals(name)) {
            try {
                msg.getResponseBody().setBody(ext.getDefaultLaunchContent());
                msg.setResponseHeader(
                        getResponseHeader("text/html; charset=UTF-8", 
                                msg.getResponseBody().length(), true));
                return msg;
            } catch (HttpMalformedHeaderException e) {
                throw new ApiException(ApiException.Type.INTERNAL_ERROR, e);
            }
        }
        throw new ApiException(ApiException.Type.BAD_OTHER, name);
    }
    
    /**
     * Methods copied (and tweaked) from the latest core to avoid bugs in the 2.6.0 core
     * TODO Remove once we've release 2.7.0
     */
    protected String getBaseURL(API.Format format, String prefix, API.RequestType type, String name, boolean proxy) {
        String apiPath = format.name() + "/" + prefix + "/" + type.name() + "/" + name + "/";
        if (!RequestType.view.equals(type)) {
            return getBaseURL(proxy) + apiPath + "?" + API.API_NONCE_PARAM + "=" + API.getInstance().getOneTimeNonce("/" + apiPath) + "&";
        }
        return getBaseURL(proxy) + apiPath;
    }

    private String getBaseURL(boolean proxy) {
        OptionsParamApi apiOpts = Model.getSingleton().getOptionsParam().getApiParam();
        ProxyParam proxyParams = Model.getSingleton().getOptionsParam().getProxyParam();
        if (proxy) {
            return apiOpts.isSecureOnly() ? API.API_URL_S : API.API_URL;
        }

        StringBuilder strBuilder = new StringBuilder(50);
        strBuilder.append("http");
        if (apiOpts.isSecureOnly()) {
            strBuilder.append('s');
        }
        strBuilder.append("://")
                .append(proxyParams.getProxyIp())
                .append(':')
                .append(proxyParams.getProxyPort())
                .append('/');
        return strBuilder.toString();
    }

}
