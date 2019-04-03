/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP development team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.pscanrulesAlpha;

import java.util.Vector;

import net.htmlparser.jericho.Source;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

public class CookieSameSiteScanner extends PluginPassiveScanner {

    /**
     * Prefix for internationalised messages used by this rule
     */
    private static final String MESSAGE_PREFIX = "pscanalpha.cookiesamesitescanner.";
    private static final int PLUGIN_ID = 10054;

    private static final String SAME_SITE_COOKIE_ATTRIBUTE = "SameSite";
    private static final String SAME_SITE_COOKIE_VALUE_STRICT = "Strict";
    private static final String SAME_SITE_COOKIE_VALUE_LAX = "Lax";
    
    private PassiveScanThread parent = null;

    @Override
    public void setParent (PassiveScanThread parent) {
        this.parent = parent;
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
        Vector<String> cookies = msg.getResponseHeader().getHeaders(cookieHeader);

        if (cookies == null) {
            return;
        }
        for (String cookie : cookies) {
            String sameSiteVal = SetCookieUtils.getAttributeValue(cookie, SAME_SITE_COOKIE_ATTRIBUTE);
            if (sameSiteVal == null) {
                // Its missing
                this.raiseAlert(msg, id, cookie, this.getDescription());
            } else if (! (sameSiteVal.equalsIgnoreCase(SAME_SITE_COOKIE_VALUE_STRICT) ||
                    sameSiteVal.equalsIgnoreCase(SAME_SITE_COOKIE_VALUE_LAX))) {
                // Its present but with an illegal value
                this.raiseAlert(msg, id, cookie,  
                        Constant.messages.getString(MESSAGE_PREFIX + "badval"));
            }
        }
        
    }
    
    private void raiseAlert(HttpMessage msg, int id, String cookieHeaderValue, String description) {
        Alert alert = new Alert(getPluginId(), Alert.RISK_LOW, Alert.CONFIDENCE_MEDIUM, 
                getName());
                alert.setDetail(
                    description, 
                    msg.getRequestHeader().getURI().toString(),
                    SetCookieUtils.getCookieName(cookieHeaderValue), "", "",
                    getSolution(), 
                    getReference(), 
                    SetCookieUtils.getSetCookiePlusName(
                            msg.getResponseHeader().toString(), cookieHeaderValue),
                    16,    // CWE Id 16 - Configuration
                    13,    // WASC Id - Info leakage
                    msg);
    
        parent.raiseAlert(id, alert);
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
}
