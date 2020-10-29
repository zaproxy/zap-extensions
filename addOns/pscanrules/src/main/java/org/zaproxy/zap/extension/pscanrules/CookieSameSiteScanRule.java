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
package org.zaproxy.zap.extension.pscanrules;

import java.util.List;
import java.util.Set;
import net.htmlparser.jericho.Source;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CookieUtils;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

public class CookieSameSiteScanRule extends PluginPassiveScanner {

    /** Prefix for internationalised messages used by this rule */
    private static final String MESSAGE_PREFIX = "pscanrules.cookiesamesite.";

    private static final int PLUGIN_ID = 10054;

    private static final String SAME_SITE_COOKIE_ATTRIBUTE = "SameSite";
    private static final String SAME_SITE_COOKIE_VALUE_STRICT = "Strict";
    private static final String SAME_SITE_COOKIE_VALUE_LAX = "Lax";

    private Model model = null;

    @Override
    public void setParent(PassiveScanThread parent) {
        // Nothing to do.
    }

    @Override
    public void scanHttpRequestSend(HttpMessage msg, int id) {
        // Ignore
    }

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        checkCookies(msg, id, HttpHeader.SET_COOKIE);
        checkCookies(msg, id, HttpHeader.SET_COOKIE2);
    }

    private void checkCookies(HttpMessage msg, int id, String cookieHeader) {
        List<String> cookies = msg.getResponseHeader().getHeaderValues(cookieHeader);

        if (cookies.isEmpty()) {
            return;
        }

        Set<String> ignoreList = CookieUtils.getCookieIgnoreList(getModel());

        for (String cookie : cookies) {
            if (ignoreList.contains(CookieUtils.getCookieName(cookie))
                    || CookieUtils.isExpired(cookie)) {
                continue;
            }
            String sameSiteVal = CookieUtils.getAttributeValue(cookie, SAME_SITE_COOKIE_ATTRIBUTE);
            if (sameSiteVal == null) {
                // Its missing
                this.raiseAlert(msg, id, cookie, this.getDescription());
            } else if (!(sameSiteVal.equalsIgnoreCase(SAME_SITE_COOKIE_VALUE_STRICT)
                    || sameSiteVal.equalsIgnoreCase(SAME_SITE_COOKIE_VALUE_LAX))) {
                // Its present but with an illegal value
                this.raiseAlert(
                        msg, id, cookie, Constant.messages.getString(MESSAGE_PREFIX + "badval"));
            }
        }
    }

    private void raiseAlert(HttpMessage msg, int id, String cookieHeaderValue, String description) {
        newAlert()
                .setRisk(Alert.RISK_LOW)
                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                .setDescription(description)
                .setParam(CookieUtils.getCookieName(cookieHeaderValue))
                .setSolution(getSolution())
                .setReference(getReference())
                .setEvidence(
                        CookieUtils.getSetCookiePlusName(
                                msg.getResponseHeader().toString(), cookieHeaderValue))
                .setCweId(16) // CWE Id 16 - Configuration
                .setWascId(13) // WASC Id - Info leakage
                .raise();
    }

    @Override
    public int getPluginId() {
        return PLUGIN_ID;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    private String getDescription() {
        return Constant.messages.getString(MESSAGE_PREFIX + "desc");
    }

    private String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    private String getReference() {
        return Constant.messages.getString(MESSAGE_PREFIX + "refs");
    }

    private Model getModel() {
        if (this.model == null) {
            this.model = Model.getSingleton();
        }
        return this.model;
    }

    /*
     * Just for use in the unit tests
     */
    protected void setModel(Model model) {
        this.model = model;
    }
}
