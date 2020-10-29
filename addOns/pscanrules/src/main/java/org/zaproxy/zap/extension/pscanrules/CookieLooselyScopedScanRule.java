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
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import net.htmlparser.jericho.Source;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CookieUtils;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/**
 * A port from a Watcher passive scanner (http://websecuritytool.codeplex.com/) rule {@code
 * CasabaSecurity.Web.Watcher.Checks.CheckPasvCookieLooselyScope}
 *
 * <p>http://websecuritytool.codeplex.com/SourceControl/changeset/view/17f2e3ded58f#Watcher%20Check%20Library%2fCheck.Pasv.Cookie.LooselyScoped.cs
 */
public class CookieLooselyScopedScanRule extends PluginPassiveScanner {

    /** Prefix for internationalized messages used by this rule */
    private static final String MESSAGE_PREFIX = "pscanrules.cookielooselyscoped.";

    private Model model = null;

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    @Override
    public void scanHttpRequestSend(HttpMessage msg, int id) {
        // do nothing
    }

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        List<HttpCookie> cookies =
                msg.getResponseHeader().getHttpCookies(msg.getRequestHeader().getHostName());

        // name of a host from which the response has been sent from
        String host = msg.getRequestHeader().getHostName();

        Set<String> ignoreList = CookieUtils.getCookieIgnoreList(getModel());

        // find all loosely scoped cookies
        List<HttpCookie> looselyScopedCookies = new LinkedList<HttpCookie>();
        for (HttpCookie cookie : cookies) {
            if (!ignoreList.contains(cookie.getName()) && isLooselyScopedCookie(cookie, host)) {
                looselyScopedCookies.add(cookie);
            }
        }

        // raise alert if have found any loosely scoped cookies
        if (looselyScopedCookies.size() > 0) {
            raiseAlert(msg, id, host, looselyScopedCookies);
        }
    }

    /*
     * Determines whether the specified cookie is loosely scoped by
     * checking it's Domain attribute value agains the host
     */
    private boolean isLooselyScopedCookie(HttpCookie cookie, String host) {
        // preconditions
        assert cookie != null;
        assert host != null;

        String cookieDomain = cookie.getDomain();

        // if Domain attribute hasn't been specified, the cookie
        // is scoped with the response host
        if (cookieDomain == null || cookieDomain.isEmpty()) {
            return false;
        }

        // Split cookie domain into sub-domains
        String[] cookieDomains = cookie.getDomain().split("\\.");
        // Split host FQDN into sub-domains
        String[] hostDomains = host.split("\\.");

        boolean isFromTheSameDomain = isCookieAndHostHaveTheSameDomain(cookieDomains, hostDomains);
        if (!isFromTheSameDomain) {
            return true;
        }
        // if cookie domain doesn't start with '.', and the domain is
        // not a second-level domain (example.com), the cookie Domain and
        // host values should match exactly
        if (!cookieDomain.startsWith(".") && cookieDomains.length >= 2 && !isFromTheSameDomain) {
            return !cookieDomain.equals(host);
        }

        // otherwise, remove the '.' and compare the result with the host
        if (cookieDomains.length != 2) {
            cookieDomains = cookieDomain.substring(1).split("\\.");
        }

        // loosely scoped domain name should have fewer sub-domains
        if (cookieDomains.length == 0 || cookieDomains.length >= hostDomains.length) {
            return false;
        }

        // and those sub-domains should match the right most sub-domains of the
        // origin domain name
        for (int i = 1; i <= cookieDomains.length; i++) {
            if (!cookieDomains[cookieDomains.length - i].equalsIgnoreCase(
                    hostDomains[hostDomains.length - i])) {
                return false;
            }
        }

        // so, the right-most domains matched, the cookie is loosely scoped
        return true;
    }

    private boolean isCookieAndHostHaveTheSameDomain(String[] cookieDomains, String[] hostDomains) {
        if (cookieDomains == null
                || hostDomains == null
                || cookieDomains[0].equalsIgnoreCase("null")
                || hostDomains[0].equalsIgnoreCase(
                        "null")) { // this happens  when we don't have any host domain
            return true;
        }
        if (!cookieDomains[cookieDomains.length - 1].equalsIgnoreCase(
                hostDomains[hostDomains.length - 1])) {
            return false;
        }
        if (cookieDomains.length < 2
                || hostDomains.length < 2
                || !cookieDomains[cookieDomains.length - 2].equalsIgnoreCase(
                        hostDomains[hostDomains.length - 2])) {
            return false;
        }
        return true;
    }

    private void raiseAlert(
            HttpMessage msg, int id, String host, List<HttpCookie> looselyScopedCookies) {

        StringBuilder sbCookies = new StringBuilder();
        for (HttpCookie cookie : looselyScopedCookies) {
            sbCookies.append(
                    Constant.messages.getString(MESSAGE_PREFIX + "extrainfo.cookie", cookie));
        }

        newAlert()
                .setRisk(Alert.RISK_INFO)
                .setConfidence(Alert.CONFIDENCE_LOW)
                .setDescription(getDescriptionMessage())
                .setOtherInfo(
                        Constant.messages.getString(MESSAGE_PREFIX + "extrainfo", host, sbCookies))
                .setSolution(getSolutionMessage())
                .setReference(getReferenceMessage())
                .setCweId(565) // CWE-565: Reliance on Cookies without Validation and Integrity
                // Checking
                .setWascId(15) // WASC-15: Application Misconfiguration
                .raise();
    }

    @Override
    public int getPluginId() {
        return 90033;
    }

    @Override
    public void setParent(PassiveScanThread parent) {
        // Nothing to do.
    }

    /*
     * Rule-associated messages
     */

    private String getDescriptionMessage() {
        return Constant.messages.getString(MESSAGE_PREFIX + "desc");
    }

    private String getSolutionMessage() {
        return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    private String getReferenceMessage() {
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
