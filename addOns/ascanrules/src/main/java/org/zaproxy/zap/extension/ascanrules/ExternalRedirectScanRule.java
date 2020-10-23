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
package org.zaproxy.zap.extension.ascanrules;

import java.io.IOException;
import java.util.List;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.HTMLElementName;
import net.htmlparser.jericho.Source;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.model.Vulnerabilities;
import org.zaproxy.zap.model.Vulnerability;

/**
 * Reviewed scan rule for External Redirect
 *
 * @author yhawke (2014)
 */
public class ExternalRedirectScanRule extends AbstractAppParamPlugin {

    /** Prefix for internationalised messages used by this rule */
    private static final String MESSAGE_PREFIX = "ascanrules.externalredirect.";

    private static final int PLUGIN_ID = 20019;

    // ZAP: Added multiple redirection types
    public static final int NO_REDIRECT = 0x00;
    public static final int REDIRECT_LOCATION_HEADER = 0x01;
    public static final int REDIRECT_REFRESH_HEADER = 0x02;
    public static final int REDIRECT_LOCATION_META = 0x03;
    public static final int REDIRECT_REFRESH_META = 0x04;
    public static final int REDIRECT_HREF_BASE = 0x05;
    public static final int REDIRECT_JAVASCRIPT = 0x06;

    private static final String OWASP_SUFFIX = ".owasp.org";
    // Use a random 'host' to prevent false positives/collisions
    // Something like: 8519918658030487947.owasp.org
    // Only need part of the UUID and abs so that we don't get negatives
    private static final String SITE_HOST =
            Long.toString(Math.abs(UUID.randomUUID().getMostSignificantBits()));
    private static final String REDIRECT_SITE = SITE_HOST + OWASP_SUFFIX;

    /** The various (prioritized) payload to try */
    private static final String[] REDIRECT_TARGETS = {
        REDIRECT_SITE,
        "http://" + REDIRECT_SITE,
        "https://" + REDIRECT_SITE,
        "http:\\\\" + REDIRECT_SITE,
        "https:\\\\" + REDIRECT_SITE,
        "//" + REDIRECT_SITE,
        "\\\\" + REDIRECT_SITE,
        "HtTp://" + REDIRECT_SITE,
        "HtTpS://" + REDIRECT_SITE,
        "URL='http://" + REDIRECT_SITE + "'",
        "5;URL='http://" + REDIRECT_SITE + "'",

        // http://kotowicz.net/absolute/
        // I never met real cases for these
        // to be evaluated in the future
        /*
        "/\\" + REDIRECT_SITE,
        "\\/" + REDIRECT_SITE,
        "\r \t//" + REDIRECT_SITE,
        "/ /" + REDIRECT_SITE,
        "http:" + REDIRECT_SITE, "https:" + REDIRECT_SITE,
        "http:/" + REDIRECT_SITE, "https:/" + REDIRECT_SITE,
        "http:////" + REDIRECT_SITE, "https:////" + REDIRECT_SITE,
        "://" + REDIRECT_SITE,
        ".:." + REDIRECT_SITE
        */
    };

    // Get WASC Vulnerability description
    private static final Vulnerability vuln = Vulnerabilities.getVulnerability("wasc_38");

    private static final Logger logger = Logger.getLogger(ExternalRedirectScanRule.class);

    @Override
    public int getId() {
        return PLUGIN_ID;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    @Override
    public String getDescription() {
        if (vuln != null) {
            return vuln.getDescription();
        }
        return "Failed to load vulnerability description from file";
    }

    @Override
    public int getCategory() {
        return Category.MISC;
    }

    @Override
    public String getSolution() {
        if (vuln != null) {
            return vuln.getSolution();
        }
        return "Failed to load vulnerability solution from file";
    }

    @Override
    public String getReference() {
        if (vuln != null) {
            StringBuilder sb = new StringBuilder();
            for (String ref : vuln.getReferences()) {
                if (sb.length() > 0) {
                    sb.append('\n');
                }

                sb.append(ref);
            }

            return sb.toString();
        }

        return "Failed to load vulnerability reference from file";
    }

    /**
     * Scan for External Redirect vulnerabilities
     *
     * @param msg a request only copy of the original message (the response isn't copied)
     * @param param the parameter name that need to be exploited
     * @param value the original parameter value
     */
    @Override
    public void scan(HttpMessage msg, String param, String value) {

        // Number of targets to try
        int targetCount = 0;

        // Debug only
        if (logger.isDebugEnabled()) {
            logger.debug("Attacking at Attack Strength: " + this.getAttackStrength());
        }

        // Figure out how aggressively we should test
        switch (this.getAttackStrength()) {
            case LOW:
                // Check only for baseline targets (2 reqs / param)
                targetCount = 3;
                break;

            case MEDIUM:
                // This works out as a total of 9 reqs / param
                targetCount = 9;
                break;

            case HIGH:
                // This works out as a total of 15 reqs / param
                targetCount = REDIRECT_TARGETS.length;
                break;

            case INSANE:
                // This works out as a total of 15 reqs / param
                targetCount = REDIRECT_TARGETS.length;
                break;

            default:
                break;
        }

        if (logger.isDebugEnabled()) {
            logger.debug(
                    "Checking ["
                            + getBaseMsg().getRequestHeader().getMethod()
                            + "]["
                            + getBaseMsg().getRequestHeader().getURI()
                            + "], parameter ["
                            + param
                            + "] for Open Redirect Vulnerabilities");
        }

        // For each target in turn
        // note that depending on the AttackLevel,
        // the number of elements that we will try changes.
        String payload;
        String redirectUrl;

        for (int h = 0; h < targetCount; h++) {

            payload = REDIRECT_TARGETS[h];

            // Get a new copy of the original message (request only) for each parameter value to try
            HttpMessage testMsg = getNewMsg();
            setParameter(testMsg, param, payload);

            if (logger.isDebugEnabled()) {
                logger.debug("Testing [" + param + "] = [" + payload + "]");
            }

            try {
                // Send the request and retrieve the response
                // Be careful: we haven't to follow redirect
                sendAndReceive(testMsg, false, false);

                // If it's a meta based injection the use the base url
                redirectUrl =
                        (payload.startsWith("5;") || payload.startsWith("URL="))
                                ? "http://" + REDIRECT_SITE
                                : payload;

                // Get back if a redirection occurs
                int redirectType = isRedirected(redirectUrl, testMsg);

                if (redirectType != NO_REDIRECT) {
                    // We Found IT!
                    // First do logging
                    if (logger.isDebugEnabled()) {
                        logger.debug(
                                "[External Redirection Found] on parameter ["
                                        + param
                                        + "] with payload ["
                                        + payload
                                        + "]");
                    }

                    newAlert()
                            .setConfidence(Alert.CONFIDENCE_MEDIUM)
                            .setParam(param)
                            .setAttack(payload)
                            .setOtherInfo(getRedirectionReason(redirectType))
                            .setEvidence(redirectUrl)
                            .setMessage(testMsg)
                            .raise();

                    // All done. No need to look for vulnerabilities on subsequent
                    // parameters on the same request (to reduce performance impact)
                    return;
                }

                // Check if the scan has been stopped
                // if yes dispose resources and exit
                if (isStop()) {
                    return;
                }

            } catch (IOException ex) {
                // Do not try to internationalize this.. we need an error message in any event..
                // if it's in English, it's still better than not having it at all.
                logger.warn(
                        "External Redirect vulnerability check failed for parameter ["
                                + param
                                + "] and payload ["
                                + payload
                                + "] due to an I/O error",
                        ex);
            }
        }
    }

    // Inner pattern used to extract the url value from a refresh content element
    private static final Pattern REFRESH_PATTERN =
            Pattern.compile("(?i)\\s*\\d+;\\s*url\\s*=\\s*(.*)");

    private String getRefreshUrl(String value) {
        Matcher matcher = REFRESH_PATTERN.matcher(value);
        return (matcher.matches()) ? matcher.group(1) : null;
    }

    /**
     * Check if the payload is a redirect
     *
     * @param value the value retrieved
     * @param payload the url that should perform external redirect
     * @return true if it's a valid open redirect
     */
    private boolean checkPayload(String value, String payload) {
        // Check both the payload and the standard url format
        return (value != null)
                && (StringUtils.startsWithIgnoreCase(value, payload)
                        || StringUtils.startsWithIgnoreCase(value, "http://" + REDIRECT_SITE));
    }

    /**
     * Check if the evil payload has been reflected in the retrieved response inside one of the
     * possible redirection points. For a (quite) complete list of the possible redirection attacks
     * please refer to http://code.google.com/p/html5security/wiki/RedirectionMethods
     *
     * @param payload the payload that should be reflected inside a redirection point
     * @param msg the current message where reflected redirection should be check into
     * @return get back the redirection type if exists
     */
    private int isRedirected(String payload, HttpMessage msg) {

        // (1) Check if redirection by "Location" header
        // http://en.wikipedia.org/wiki/HTTP_location
        // HTTP/1.1 302 Found
        // Location: http://www.example.org/index.php
        //
        String value = msg.getResponseHeader().getHeader(HttpHeader.LOCATION);
        if (checkPayload(value, payload)) {
            return REDIRECT_LOCATION_HEADER;
        }

        // (2) Check if redirection by "Refresh" header
        // http://en.wikipedia.org/wiki/URL_redirection
        // HTTP/1.1 200 ok
        // Refresh: 0; url=http://www.example.com/
        //
        value = msg.getResponseHeader().getHeader("Refresh");
        if (value != null) {
            // Usually redirect content is configured with a delay
            // so extract the url component
            value = getRefreshUrl(value);

            if (checkPayload(value, payload)) {
                return REDIRECT_REFRESH_HEADER;
            }
        }

        // (3) Check if redirection occurs by "Meta" content header
        // http://code.google.com/p/html5security/wiki/RedirectionMethods
        // <meta http-equiv="location" content="URL=http://evil.com" />
        // <meta http-equiv="refresh" content="0;url=http://evil.com/" />
        //
        String content = msg.getResponseBody().toString();
        Source htmlSrc = new Source(content);
        List<Element> metaElements = htmlSrc.getAllElements(HTMLElementName.META);
        for (Element el : metaElements) {

            value = el.getAttributeValue("http-equiv");

            if (value != null) {
                if (value.equalsIgnoreCase("location")) {
                    // Get the content attribute value
                    value = el.getAttributeValue("content");

                    // Check if the payload is inside the location attribute
                    if (checkPayload(value, payload)) {
                        return REDIRECT_LOCATION_META;
                    }

                } else if (value.equalsIgnoreCase("refresh")) {
                    // Get the content attribute value
                    value = el.getAttributeValue("content");

                    // If the content attribute isn't set go away
                    if (value != null) {
                        // Usually redirect content is configured with a delay
                        // so extract the url component
                        value = getRefreshUrl(value);

                        // Check if the payload is inside the location attribute
                        if (checkPayload(value, payload)) {
                            return REDIRECT_REFRESH_META;
                        }
                    }
                }
            }
        }

        // (4) Check if redirection occurs by Base Tag
        // http://code.google.com/p/html5security/wiki/RedirectionMethods
        // <base href="http://evil.com/" />
        //

        // (5) Check if redirection occurs by Javascript
        // http://code.google.com/p/html5security/wiki/RedirectionMethods
        // location='http://evil.com/';
        // location.href='http://evil.com/';
        // location.reload('http://evil.com/');
        // location.replace('http://evil.com/');
        // location.assign('http://evil.com/');
        // window.open('http://evil.com/');
        // window.navigate('http://evil.com/');
        //
        if (StringUtils.indexOfIgnoreCase(content, payload) != -1) {
            List<Element> jsElements = htmlSrc.getAllElements(HTMLElementName.SCRIPT);
            String matchingUrl = "(\\Q" + payload + "\\E|\\Qhttp://" + REDIRECT_SITE + "\\E)";
            Pattern pattern;

            for (Element el : jsElements) {
                value = el.getContent().toString();

                // location='http://evil.com/';
                // location.href='http://evil.com/';
                pattern =
                        Pattern.compile("(?i)location(\\.href)?\\s*=\\s*('|\")\\s*" + matchingUrl);
                if (pattern.matcher(value).find()) {
                    return REDIRECT_JAVASCRIPT;
                }

                // location.reload('http://evil.com/');
                // location.replace('http://evil.com/');
                // location.assign('http://evil.com/');
                pattern =
                        Pattern.compile(
                                "(?i)location\\.(replace|reload|assign)\\s*\\(\\s*('|\")\\s*"
                                        + matchingUrl);
                if (pattern.matcher(value).find()) {
                    return REDIRECT_JAVASCRIPT;
                }

                // window.open('http://evil.com/');
                // window.navigate('http://evil.com/');
                pattern =
                        Pattern.compile(
                                "(?i)window\\.(open|navigate)\\s*\\(\\s*('|\")\\s*" + matchingUrl);
                if (pattern.matcher(value).find()) {
                    return REDIRECT_JAVASCRIPT;
                }
            }
        }

        return NO_REDIRECT;
    }

    /**
     * Get a readable reason for the found redirection
     *
     * @param type the redirection type
     * @return a string representing the reason of this redirection
     */
    private String getRedirectionReason(int type) {
        switch (type) {
            case REDIRECT_LOCATION_HEADER:
                return Constant.messages.getString(MESSAGE_PREFIX + "reason.location.header");

            case REDIRECT_LOCATION_META:
                return Constant.messages.getString(MESSAGE_PREFIX + "reason.location.meta");

            case REDIRECT_REFRESH_HEADER:
                return Constant.messages.getString(MESSAGE_PREFIX + "reason.refresh.header");

            case REDIRECT_REFRESH_META:
                return Constant.messages.getString(MESSAGE_PREFIX + "reason.refresh.meta");

            case REDIRECT_JAVASCRIPT:
                return Constant.messages.getString(MESSAGE_PREFIX + "reason.javascript");
        }

        return Constant.messages.getString(MESSAGE_PREFIX + "reason.notfound");
    }

    /**
     * Give back the risk associated to this vulnerability (high)
     *
     * @return the risk according to the Alert enum
     */
    @Override
    public int getRisk() {
        return Alert.RISK_HIGH;
    }

    /**
     * http://cwe.mitre.org/data/definitions/601.html
     *
     * @return the official CWE id
     */
    @Override
    public int getCweId() {
        return 601;
    }

    /**
     * http://projects.webappsec.org/w/page/13246981/URL%20Redirector%20Abuse
     *
     * @return the official WASC id
     */
    @Override
    public int getWascId() {
        return 38;
    }
}
