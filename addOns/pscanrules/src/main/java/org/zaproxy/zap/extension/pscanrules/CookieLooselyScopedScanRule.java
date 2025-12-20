/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2012 The ZAP Development Team
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

import java.net.HttpCookie;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import net.htmlparser.jericho.Source;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.CookieUtils;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

public class CookieLooselyScopedScanRule extends PluginPassiveScanner
        implements CommonPassiveScanRuleInfo {

    /** Prefix for internationalized messages used by this rule */
    private static final String MESSAGE_PREFIX = "pscanrules.cookielooselyscoped.";

    private static final Map<String, String> ALERT_TAGS;

    static {
        Map<String, String> alertTags =
                new HashMap<>(
                        CommonAlertTag.toMap(
                                CommonAlertTag.OWASP_2021_A08_INTEGRITY_FAIL,
                                CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG,
                                CommonAlertTag.WSTG_V42_SESS_02_COOKIE_ATTRS,
                                CommonAlertTag.SYSTEMIC));
        alertTags.put(PolicyTag.PENTEST.getTag(), "");
        alertTags.put(PolicyTag.DEV_STD.getTag(), "");
        alertTags.put(PolicyTag.QA_STD.getTag(), "");
        ALERT_TAGS = Collections.unmodifiableMap(alertTags);
    }

    private Model model = null;

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        List<HttpCookie> cookies =
                msg.getResponseHeader().getHttpCookies(msg.getRequestHeader().getHostName());

        // name of a host from which the response has been sent from
        String host = msg.getRequestHeader().getHostName();

        Set<String> ignoreList = CookieUtils.getCookieIgnoreList(getModel());

        // find all loosely scoped cookies
        List<HttpCookie> looselyScopedCookies = new LinkedList<>();
        for (HttpCookie cookie : cookies) {
            if (!ignoreList.contains(cookie.getName()) && isLooselyScopedCookie(cookie, host)) {
                looselyScopedCookies.add(cookie);
            }
        }

        // raise an alert if any loosely scoped cookies were found
        if (!looselyScopedCookies.isEmpty()) {
            buildAlert(host, looselyScopedCookies).raise();
        }
    }

    /*
     * Determines whether the specified cookie is loosely scoped by
     * checking its Domain attribute value against the origin domain
     *
     * Compliant with RFC 6265 (https://datatracker.ietf.org/doc/html/rfc6265#section-4.1.2.3).
     */
    private static boolean isLooselyScopedCookie(HttpCookie cookie, String originDomain) {
        // preconditions
        assert cookie != null;
        assert originDomain != null;

        String cookieDomain = cookie.getDomain();

        // No problem here since by default the cookie is
        // scoped to the origin, not including subdomains
        if (cookieDomain == null || cookieDomain.isEmpty()) {
            return false;
        }

        cookieDomain = cookieDomain.toLowerCase();
        originDomain = originDomain.toLowerCase();

        // If the cookie domain starts with a leading dot,
        // remove it as per RFC (ignore the dot)
        if (cookieDomain.startsWith(".")) {
            cookieDomain = cookieDomain.substring(1);
        }

        // According to the RFC, the cookie domain must either be the same as
        // the origin domain or a higher-order domain. Therefore, if the cookieDomain
        // is more specific (lower order) than the originDomain, the cookie is invalid
        // and cannot be considered loosely scoped.
        if (cookieDomain.equals(originDomain) || cookieDomain.length() > originDomain.length()) {
            return false;
        }

        // If the cookie domain is a higher-order domain
        // (cookieDomain is "example.com", originDomain is "sub.example.com")
        // it is considered loosely scoped
        return originDomain.endsWith("." + cookieDomain);
    }

    private AlertBuilder buildAlert(String host, List<HttpCookie> looselyScopedCookies) {

        StringBuilder sbCookies = new StringBuilder();
        for (HttpCookie cookie : looselyScopedCookies) {
            sbCookies.append(
                    Constant.messages.getString(MESSAGE_PREFIX + "extrainfo.cookie", cookie));
        }

        return newAlert()
                .setRisk(Alert.RISK_INFO)
                .setConfidence(Alert.CONFIDENCE_LOW)
                .setDescription(Constant.messages.getString(MESSAGE_PREFIX + "desc"))
                .setOtherInfo(
                        Constant.messages.getString(MESSAGE_PREFIX + "extrainfo", host, sbCookies))
                .setSolution(Constant.messages.getString(MESSAGE_PREFIX + "soln"))
                .setReference(Constant.messages.getString(MESSAGE_PREFIX + "refs"))
                .setCweId(565) // CWE-565: Reliance on Cookies without Validation and Integrity)
                .setWascId(15); // WASC-15: Application Misconfiguration)
    }

    @Override
    public List<Alert> getExampleAlerts() {
        return List.of(
                buildAlert(
                                "subdomain.example.com",
                                HttpCookie.parse("name=value; domain=example.com"))
                        .build());
    }

    @Override
    public int getPluginId() {
        return 90033;
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
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
