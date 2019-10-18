/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP Development Team
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
package org.zaproxy.zap.extension.csphelper;

import net.sf.json.JSONObject;
import org.apache.log4j.Logger;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.extension.api.ApiImplementor;
import org.zaproxy.zap.extension.api.ApiResponse;

public class CspHelperAPI extends ApiImplementor {

    private static Logger LOGGER = Logger.getLogger(CspHelperAPI.class);

    private static final String PREFIX = "csphelper";

    private ExtensionCspHelper extension;

    public CspHelperAPI(ExtensionCspHelper extension) {
        this.extension = extension;
    }

    @Override
    public String handleCallBack(HttpMessage msg) {
        String cspReportStr = msg.getRequestBody().toString();
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Got CSP report URL: " + msg.getRequestHeader().getURI().toString());
            LOGGER.debug("Got CSP report header: " + msg.getRequestHeader().toString());
            LOGGER.debug("Got CSP report body: " + cspReportStr);
            if (View.isInitialised()) {
                View.getSingleton().getOutputPanel().append("CSP report: " + cspReportStr + "\n");
            }
        }

        /*
        	{"csp-report":
        {"blocked-uri":"https://a.tiles.mapbox.com",
        "document-uri":"https://location-leaderboard.services.mozilla.com/?",
        "original-policy":"script-src https://location-leaderboard.services.mozilla.com https://www.google-analytics.com https://www.mozilla.org 'sha256-Ri/knIQy+te80bBUW2ViOjxeh+qSuEtuLCIT0mCqX7U=' https://mozorg.cdn.mozilla.net 'sha256-AYi4XWyJ3ZJ+CDDQsXgrBM9ux/hJVCdnJbwQ3vCgc/Y=' https://www.mozilla.org; style-src https://location-leaderboard.services.mozilla.com https://www.mozilla.org https://www.mozilla.org; img-src https://location-leaderboard.services.mozilla.com; font-src https://location-leaderboard.services.mozilla.com; report-uri https://location-leaderboard.services.mozilla.com/zapCallBackUrl/748397825097318944",
        "referrer":"",
        "violated-directive":"img-src https://location-leaderboard.services.mozilla.com"}}
        */
        try {
            JSONObject report = JSONObject.fromObject(cspReportStr);

            JSONObject cspReport = report.getJSONObject("csp-report");
            String blockedUri = cspReport.getString("blocked-uri");
            LOGGER.debug("Got blockedUri: " + blockedUri);
            String violated = cspReport.getString("violated-directive");
            LOGGER.debug("Got violated: " + violated);
            if (violated != null) {
                String[] split = violated.split(" ");
                if (split.length > 1) {
                    String src = split[0];
                    String url = cspReport.getString("document-uri");
                    CSP csp = this.extension.getCspForUrl(url);
                    if (csp != null) {
                        LOGGER.debug("Got csp: " + csp);
                        CspElement elem = csp.getSource(src);
                        if (elem != null) {
                            LOGGER.debug("Got elem: " + elem);
                            if (blockedUri.equals("self")) {
                                elem.setSelf();
                            } else if (blockedUri.startsWith("data:")) {
                                elem.setData();
                            } else if (blockedUri.startsWith("mediastream:")) {
                                elem.setMediastream();
                            } else if (blockedUri.startsWith("blob:")) {
                                elem.setBlob();
                            } else if (blockedUri.startsWith("filesystem:")) {
                                elem.setFilesystem();
                            } else {
                                elem.addUrl(blockedUri);
                            }
                            // Set unsafe-inline if JS found in on* event attributes
                            if (src.equalsIgnoreCase("script-src")
                                    && cspReport.has("script-sample")) {
                                // Get script-sample
                                String sample = cspReport.getString("script-sample");
                                if (sample != null
                                        && sample.matches(
                                                "[\\w\\s]*(on[a-zA-Z]+)\\sattribute[\\w\\s]*")) {
                                    LOGGER.debug("Fixing inline JS with unsafe-inline: " + sample);
                                    elem.setUnsafeInline();
                                }
                            }
                        } else {
                            LOGGER.debug("Unhandled element: " + src);
                            if (View.isInitialised()) {
                                View.getSingleton()
                                        .getOutputPanel()
                                        .append("CSP: Unhandled element: " + src + "\n");
                            }
                        }
                    } else {
                        LOGGER.debug("No CSP for URL : " + url);
                        if (View.isInitialised()) {
                            View.getSingleton()
                                    .getOutputPanel()
                                    .append("CSP: No CSP for URL : " + url + "\n");
                        }
                    }
                } else {
                    LOGGER.debug("Unexcepted data : " + violated);
                    if (View.isInitialised()) {
                        View.getSingleton()
                                .getOutputPanel()
                                .append("CSP: Unexcepted data : " + violated + "\n");
                    }
                }
            }
        } catch (Exception e) {
            LOGGER.error(e.getStackTrace());
        }

        return "";
    }

    @Override
    public ApiResponse handleApiOptionAction(String name, JSONObject params) throws ApiException {
        return null;
    }

    @Override
    public HttpMessage handleApiOther(HttpMessage msg, String name, JSONObject params) {
        return null;
    }

    @Override
    public ApiResponse handleApiView(String name, JSONObject params) throws ApiException {
        return null;
    }

    @Override
    public String getPrefix() {
        return PREFIX;
    }
}
