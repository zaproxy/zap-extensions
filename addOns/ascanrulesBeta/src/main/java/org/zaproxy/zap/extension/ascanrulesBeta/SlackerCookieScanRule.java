/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
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
package org.zaproxy.zap.extension.ascanrulesBeta;

import java.io.IOException;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Locale;
import java.util.Set;
import java.util.TreeSet;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.model.Vulnerabilities;
import org.zaproxy.zap.model.Vulnerability;

/**
 * Goal: automate discovery of areas of a website where authentication via session cookies, or
 * content controlled by preference cookies, is not actually enforced.
 *
 * <p>Method: checks one by one if cookies really used for rendering a page at given URI, based on
 * length in bytes of response compared to baseline request.
 *
 * <p>For example if 5 cookies exist, 5 new GET requests executed, each time dropping a different
 * cookie and noting any change in the response length. A site with only tracking cookies will get
 * an INFO alert but may be working as designed.
 *
 * <p>With thanks to Kaiser Permanente CyberSecurity comrades for using and feedback.
 */
public class SlackerCookieScanRule extends AbstractAppPlugin {
    // http://projects.webappsec.org/w/page/13246978/Threat%20Classification
    // going to classify this as #45, Fingerprinting.
    // #01, Authentication could be applicable.
    private static final String[] HIGH_RISK_COOKIE_NAMES = {"session", "userid"};
    private static Vulnerability vuln = Vulnerabilities.getVulnerability("wasc_45");
    private static Logger log = Logger.getLogger(SlackerCookieScanRule.class);

    @Override
    public void scan() {

        int baseResponseLength = getBaseMsg().getResponseBody().length();
        Set<HtmlParameter> cookies = getBaseMsg().getCookieParams();

        Set<String> cookiesThatMakeADifference = new HashSet<String>();
        Set<String> cookiesThatDoNOTMakeADifference = new HashSet<String>();

        boolean thereAreSlackCookies = false;
        HttpMessage msg = getNewMsg();

        for (HtmlParameter oneCookie : cookies) {
            thereAreSlackCookies =
                    repeatRequestWithoutOneCookie(
                            msg,
                            baseResponseLength,
                            cookies,
                            cookiesThatMakeADifference,
                            cookiesThatDoNOTMakeADifference,
                            thereAreSlackCookies,
                            oneCookie);

            boolean sessionWentBad =
                    refreshSessionAllCookies(msg, cookies, oneCookie, baseResponseLength);
            // Quit if active scanning has been stopped, or we lost session
            // integrity
            if (isStop() || sessionWentBad) {
                return;
            }
        }

        if (thereAreSlackCookies) {
            raiseAlert(msg, cookies, cookiesThatMakeADifference, cookiesThatDoNOTMakeADifference);
        }
    }

    private boolean refreshSessionAllCookies(
            HttpMessage msg,
            Set<HtmlParameter> cookies,
            HtmlParameter oneCookie,
            int baseResponseLength) {

        boolean sessionNoLongerGood = false;
        msg.setCookieParams(new TreeSet<HtmlParameter>(cookies));

        try {
            sendAndReceive(msg, false);
            if (msg.getResponseBody().length() != baseResponseLength) {
                sessionNoLongerGood = true;
                newAlert()
                        .setConfidence(Alert.CONFIDENCE_LOW)
                        .setOtherInfo(getSessionDestroyedText(oneCookie.getName()))
                        .setMessage(msg)
                        .raise();
            }
        } catch (IOException io) {
            log.debug("Blew up trying to refresh session with all cookies: " + io.getMessage());
        }
        return sessionNoLongerGood;
    }

    /**
     * This is where the real work happens, we resubmit a GET to same URI but dropping one cookie,
     * and see if response is different.
     */
    private boolean repeatRequestWithoutOneCookie(
            HttpMessage msg,
            int baseResponseLength,
            Set<HtmlParameter> cookies,
            Set<String> cookiesThatMakeADifference,
            Set<String> cookiesThatDoNOTMakeADifference,
            boolean thereAreSlackCookies,
            HtmlParameter oneCookie) {

        boolean doesCookieChangeResponse = sendOneRequest(cookies, oneCookie, baseResponseLength);
        if (doesCookieChangeResponse) {
            cookiesThatMakeADifference.add(oneCookie.getName());
        } else {
            thereAreSlackCookies = true;
            cookiesThatDoNOTMakeADifference.add(oneCookie.getName());
        }

        return thereAreSlackCookies;
    }

    /**
     * Looks as if one needs to manually add cookies to each synthetic GET
     *
     * @param cookies
     * @param oneCookie
     * @param baseResponseLength
     */
    private boolean sendOneRequest(
            Set<HtmlParameter> cookies, HtmlParameter oneCookie, int baseResponseLength) {

        HttpMessage msg = getNewMsg();

        boolean doesThisCookieMatter = false;
        TreeSet<HtmlParameter> allCookiesExceptOne = new TreeSet<HtmlParameter>();
        for (HtmlParameter cookieCandidate : cookies) {
            if (cookieCandidate != oneCookie) allCookiesExceptOne.add(cookieCandidate);
        }
        msg.setCookieParams(allCookiesExceptOne);
        try {
            // Send the request and retrieve the response
            sendAndReceive(msg, false);
            int responseLength = msg.getResponseBody().length();

            if (log.isDebugEnabled()) {
                log.debug(
                        "trying to exclude cookie "
                                + oneCookie.getName()
                                + ", request header=>"
                                + msg.getRequestHeader().getHeadersAsString());
                log.debug(
                        "response length was:"
                                + responseLength
                                + ", while baseResponseLength was: "
                                + baseResponseLength);
            }

            if (responseLength != baseResponseLength) {
                doesThisCookieMatter = true;
            }

        } catch (IOException ex) {
            log.debug("caught IOException in SlackerCookieScanRule: " + ex.getMessage());
        }
        return doesThisCookieMatter;
    }

    private void raiseAlert(
            HttpMessage msg,
            Set<HtmlParameter> cookies,
            Set<String> cookiesThatMakeADifference,
            Set<String> cookiesThatDoNOTMakeADifference) {

        StringBuilder otherInfoBuff =
                createOtherInfoText(cookiesThatMakeADifference, cookiesThatDoNOTMakeADifference);

        int riskLevel = calculateRisk(cookiesThatDoNOTMakeADifference, otherInfoBuff);

        newAlert()
                .setRisk(riskLevel)
                .setConfidence(Alert.CONFIDENCE_LOW)
                .setOtherInfo(otherInfoBuff.toString())
                .setMessage(msg)
                .raise();
    }

    private StringBuilder createOtherInfoText(
            Set<String> cookiesThatMakeADifference, Set<String> cookiesThatDoNOTMakeADifference) {

        StringBuilder otherInfoBuff =
                new StringBuilder(
                        Constant.messages.getString("ascanbeta.cookieslack.otherinfo.intro"));

        otherInfoBuff.append(getAffectResponseYes());
        listCookies(cookiesThatMakeADifference, otherInfoBuff);

        otherInfoBuff.append(getAffectResponseNo());
        listCookies(cookiesThatDoNOTMakeADifference, otherInfoBuff);

        return otherInfoBuff;
    }

    private void listCookies(Set<String> cookieSet, StringBuilder otherInfoBuff) {
        Iterator<String> itYes = cookieSet.iterator();
        while (itYes.hasNext()) {
            formatCookiesList(otherInfoBuff, itYes);
        }
        otherInfoBuff.append(getEOL());
    }

    private int calculateRisk(
            Set<String> cookiesThatDoNOTMakeADifference, StringBuilder otherInfoBuff) {
        int riskLevel = Alert.RISK_INFO;
        for (String cookie : cookiesThatDoNOTMakeADifference) {
            for (String risky_cookie : HIGH_RISK_COOKIE_NAMES) {
                if (cookie.toLowerCase(Locale.ROOT).indexOf(risky_cookie) > -1) {
                    // time to worry: we dropped a likely session cookie, but no
                    // change in response
                    riskLevel = Alert.RISK_LOW;
                    otherInfoBuff.insert(0, getSessionCookieWarning(cookie));
                }
            }
        }
        return riskLevel;
    }

    private String getSessionDestroyedText(String cookie) {
        return Constant.messages.getString("ascanbeta.cookieslack.session.destroyed", cookie);
    }

    private String getAffectResponseYes() {
        return Constant.messages.getString("ascanbeta.cookieslack.affect.response.yes");
    }

    private String getAffectResponseNo() {
        return Constant.messages.getString("ascanbeta.cookieslack.affect.response.no");
    }

    private String getSeparator() {
        return Constant.messages.getString("ascanbeta.cookieslack.separator");
    }

    private String getEOL() {
        return Constant.messages.getString("ascanbeta.cookieslack.endline");
    }

    private void formatCookiesList(StringBuilder otherInfoBuff, Iterator<String> cookieIterator) {

        otherInfoBuff.append(cookieIterator.next());
        if (cookieIterator.hasNext()) {
            otherInfoBuff.append(getSeparator());
        }
    }

    private String getSessionCookieWarning(String cookie) {
        return Constant.messages.getString("ascanbeta.cookieslack.session.warning", cookie);
    }

    @Override
    public int getId() {
        return 90027;
    }

    @Override
    public String getName() {
        return Constant.messages.getString("ascanbeta.cookieslack.name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("ascanbeta.cookieslack.desc");
    }

    @Override
    public int getCategory() {
        return Category.INFO_GATHER;
    }

    @Override
    public String getSolution() {
        return "";
    }

    @Override
    public String getReference() {
        if (vuln != null) {
            StringBuilder sb = new StringBuilder();
            for (String ref : vuln.getReferences()) {
                if (sb.length() > 0) {
                    sb.append("\n");
                }
                sb.append(ref);
            }
            return sb.toString();
        }
        return "Cookie Slack Detector: Failed to load vulnerability reference from file";
    }

    @Override
    public int getRisk() {
        return Alert.RISK_INFO;
    }

    @Override
    public int getCweId() {
        // The CWE id - 200 is closest thing to fingerprinting
        return 200;
    }

    @Override
    public int getWascId() {
        // The WASC ID - fingerprinting
        return 45;
    }
}
