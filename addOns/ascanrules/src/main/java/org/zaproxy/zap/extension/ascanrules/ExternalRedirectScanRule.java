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
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.HTMLElementName;
import net.htmlparser.jericho.Source;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.addon.commonlib.http.HttpFieldsNames;
import org.zaproxy.addon.commonlib.vulnerabilities.Vulnerabilities;
import org.zaproxy.addon.commonlib.vulnerabilities.Vulnerability;

/**
 * Reviewed scan rule for External Redirect
 *
 * @author yhawke (2014)
 */
public class ExternalRedirectScanRule extends AbstractAppParamPlugin
        implements CommonActiveScanRuleInfo {

    private static final String MESSAGE_PREFIX = "ascanrules.externalredirect.";
    private static final Vulnerability VULN = Vulnerabilities.getDefault().get("wasc_38");
    private static final Logger LOGGER = LogManager.getLogger(ExternalRedirectScanRule.class);

    private static final Map<String, String> ALERT_TAGS;

    static {
        Map<String, String> alertTags =
                new HashMap<>(
                        CommonAlertTag.toMap(
                                CommonAlertTag.OWASP_2021_A03_INJECTION,
                                CommonAlertTag.OWASP_2017_A01_INJECTION,
                                CommonAlertTag.WSTG_V42_CLNT_04_OPEN_REDIR,
                                CommonAlertTag.HIPAA));
        alertTags.put(PolicyTag.API.getTag(), "");
        alertTags.put(PolicyTag.DEV_CICD.getTag(), "");
        alertTags.put(PolicyTag.DEV_STD.getTag(), "");
        alertTags.put(PolicyTag.DEV_FULL.getTag(), "");
        alertTags.put(PolicyTag.QA_STD.getTag(), "");
        alertTags.put(PolicyTag.QA_FULL.getTag(), "");
        alertTags.put(PolicyTag.SEQUENCE.getTag(), "");
        alertTags.put(PolicyTag.PENTEST.getTag(), "");
        ALERT_TAGS = Collections.unmodifiableMap(alertTags);
    }

    private static final int PLUGIN_ID = 20019;
    private static final String ORIGINAL_VALUE_PLACEHOLDER = "@@@original@@@";

    private enum RedirectType {
        NONE("", ""),
        LOCATION_HEADER(
                "-1", Constant.messages.getString(MESSAGE_PREFIX + "reason.location.header")),
        REFRESH_HEADER("-2", Constant.messages.getString(MESSAGE_PREFIX + "reason.refresh.header")),
        LOCATION_META("-3", Constant.messages.getString(MESSAGE_PREFIX + "reason.location.meta")),
        REFRESH_META("-3", Constant.messages.getString(MESSAGE_PREFIX + "reason.refresh.meta")),
        JAVASCRIPT("-4", Constant.messages.getString(MESSAGE_PREFIX + "reason.javascript"));

        private String alertReference;
        private String reason;

        RedirectType(String ref, String reason) {
            this.alertReference = PLUGIN_ID + ref;
            this.reason = reason;
        }

        public String getAlertReference() {
            return this.alertReference;
        }

        public String getReason() {
            return this.reason;
        }
    }

    private static final String OWASP_SUFFIX = ".owasp.org";
    // Use a random 'host' to prevent false positives/collisions
    // Something like: 8519918658030487947.owasp.org
    // Only need part of the UUID and abs so that we don't get negatives
    private static final String SITE_HOST =
            Long.toString(Math.abs(UUID.randomUUID().getMostSignificantBits()));
    private static final String REDIRECT_SITE = SITE_HOST + OWASP_SUFFIX;

    private static final String SITE_PATT = "https?://" + REDIRECT_SITE;
    // location='http://evil.com/';
    // location.href='http://evil.com/';
    private static final Pattern JS_LOCATION_PATT =
            Pattern.compile("(?i)location(?:\\.href)?\\s*=\\s*['\"](" + SITE_PATT + ")['\"]");
    // location.reload('http://evil.com/');
    // location.replace('http://evil.com/');
    // location.assign('http://evil.com/');
    private static final Pattern JS_LOCATION_EXTENDED_PATT =
            Pattern.compile(
                    "(?i)location\\.(?:replace|reload|assign)\\s*\\(\\s*['\"]("
                            + SITE_PATT
                            + ")['\"]");
    // window.open('http://evil.com/');
    // window.navigate('http://evil.com/');
    private static final Pattern JS_WINDOW_PATT =
            Pattern.compile(
                    "(?i)window\\.(?:open|navigate)\\s*\\(\\s*['\"](" + SITE_PATT + ")['\"]");

    /** The various (prioritized) payloads to try */
    private enum RedirectPayloads {
        PLAIN_SITE(REDIRECT_SITE, false),
        HTTPS_SITE(HttpHeader.SCHEME_HTTPS + REDIRECT_SITE, false),
        // Double encode the dots
        HTTPS_PERIOD_ENCODE(HttpHeader.SCHEME_HTTPS + REDIRECT_SITE.replace(".", "%2e"), false),
        HTTPS_REFRESH(
                "5;URL='https://" + REDIRECT_SITE + "'",
                false,
                HttpHeader.SCHEME_HTTPS + REDIRECT_SITE),
        HTTP_LOCATION(
                "URL='http://" + REDIRECT_SITE + "'",
                false,
                HttpHeader.SCHEME_HTTP + REDIRECT_SITE),
        // Simple allow list bypass, ex: https://evil.com?<original_value>
        // Where <original_value> is whatever the parameter value initially was, ex:
        // https://good.expected.com
        HTTPS_ORIG_PARAM(
                HttpHeader.SCHEME_HTTPS + REDIRECT_SITE + "/?" + ORIGINAL_VALUE_PLACEHOLDER, true),
        HTTPS_REFRESH_ORIG_PARAM(
                "5;URL='https://" + REDIRECT_SITE + "/?" + ORIGINAL_VALUE_PLACEHOLDER + "'",
                true,
                HttpHeader.SCHEME_HTTPS + REDIRECT_SITE),
        HTTPS_WRONG_SLASH(HttpHeader.SCHEME_HTTPS + "\\" + REDIRECT_SITE, false),
        HTTP_WRONG_SLASH(HttpHeader.SCHEME_HTTP + "\\" + REDIRECT_SITE, false),
        HTTP(HttpHeader.SCHEME_HTTP + REDIRECT_SITE, false),
        NO_SCHEME("//" + REDIRECT_SITE, false),
        NO_SCHEME_WRONG_SLASH("\\\\" + REDIRECT_SITE, false),
        HTTPS_MIXED_CASE("HtTpS://" + REDIRECT_SITE, false),
        HTTP_MIXED_CASE("HtTp://" + REDIRECT_SITE, false);

        /* http://kotowicz.net/absolute/
        I never met real cases for these
        to be evaluated in the future
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

        private final String payload;
        private final boolean placeholder;
        private final String redirectUrl;

        RedirectPayloads(String payload, boolean placeholder, String redirectUrl) {
            this.payload = payload;
            this.placeholder = placeholder;
            this.redirectUrl = redirectUrl;
        }

        RedirectPayloads(String payload, boolean placeholder) {
            this(payload, placeholder, payload);
        }

        public String getInjection(String value) {
            return placeholder ? payload.replace(ORIGINAL_VALUE_PLACEHOLDER, value) : payload;
        }

        public String getRedirectUrl() {
            return redirectUrl;
        }
    }

    private int payloadCount;

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
        return VULN.getDescription();
    }

    @Override
    public int getCategory() {
        return Category.MISC;
    }

    @Override
    public String getSolution() {
        return VULN.getSolution();
    }

    @Override
    public String getReference() {
        return VULN.getReferencesAsString();
    }

    @Override
    public void init() {
        LOGGER.debug("Attacking at Attack Strength: {}", this.getAttackStrength());

        // Figure out how aggressively we should test
        payloadCount =
                switch (this.getAttackStrength()) {
                    case LOW -> 3;
                    case MEDIUM -> 9;
                    case HIGH, INSANE -> RedirectPayloads.values().length;
                    default -> 9;
                };
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
        LOGGER.debug(
                "Checking [{}][{}], parameter [{}] for Open Redirect Vulnerabilities",
                getBaseMsg().getRequestHeader().getMethod(),
                getBaseMsg().getRequestHeader().getURI(),
                param);

        String redirectUrl;
        int payloadIdx = 0;

        for (RedirectPayloads payload : RedirectPayloads.values()) {
            if (isStop() || payloadIdx == payloadCount) {
                return;
            }

            String injection = payload.getInjection(value);

            HttpMessage testMsg = getNewMsg();
            setParameter(testMsg, param, injection);

            LOGGER.debug("Testing [{}] = [{}]", param, injection);

            try {
                // Be careful: don't follow redirect
                sendAndReceive(testMsg, false);

                redirectUrl = payload.getRedirectUrl();

                RedirectType redirectType = isRedirected(redirectUrl, testMsg);

                if (redirectType != RedirectType.NONE) {
                    LOGGER.debug(
                            "[External Redirection Found] on parameter [{}] with payload [{}]",
                            param,
                            injection);

                    buildAlert(param, injection, redirectType, redirectUrl, testMsg).raise();
                    return;
                }
            } catch (IOException ex) {
                LOGGER.warn(
                        "External Redirect vulnerability check failed for parameter [{}] and payload [{}] due to an I/O error",
                        param,
                        injection,
                        ex);
            }
            payloadIdx++;
        }
    }

    private AlertBuilder buildAlert(
            String param,
            String payload,
            RedirectType redirectType,
            String evidence,
            HttpMessage testMsg) {

        return newAlert()
                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                .setParam(param)
                .setAttack(payload)
                .setOtherInfo(redirectType.getReason())
                .setEvidence(evidence)
                .setAlertRef(redirectType.getAlertReference())
                .setMessage(testMsg);
    }

    private static final Pattern REFRESH_PATTERN =
            Pattern.compile("(?i)\\s*\\d+\\s*;\\s*url\\s*=\\s*[\"']?([^'\"]*)[\"']?");

    static String getRefreshUrl(String value) {
        Matcher matcher = REFRESH_PATTERN.matcher(value);
        return matcher.matches() ? matcher.group(1) : null;
    }

    private static final Pattern LOCATION_PATTERN =
            Pattern.compile("(?i)^\\s*url\\s*=\\s*[\"']?([^'\"]*)[\"']?");

    static String getLocationUrl(String value) {
        Matcher matcher = LOCATION_PATTERN.matcher(value);
        return matcher.find() ? matcher.group(1) : null;
    }

    /**
     * Check if the payload is a redirect
     *
     * @param value the value retrieved
     * @return true if it's a valid open redirect
     */
    private static boolean checkPayload(String value) {
        if (value == null || !StringUtils.startsWithIgnoreCase(value, HttpHeader.HTTP)) {
            return false;
        }

        try {
            return isRedirectHost(value, true);
        } catch (URIException e) {
            LOGGER.debug(e.getMessage(), e);
            try {
                return isRedirectHost(value, false);
            } catch (URIException ex) {
                LOGGER.debug(ex.getMessage(), ex);
                return false;
            }
        }
    }

    private static boolean isRedirectHost(String value, boolean escaped) throws URIException {
        URI locUri = new URI(value, escaped);
        return REDIRECT_SITE.equalsIgnoreCase(locUri.getHost());
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
    private static RedirectType isRedirected(String payload, HttpMessage msg) {

        // (1) Check if redirection by "Location" header
        // http://en.wikipedia.org/wiki/HTTP_location
        // HTTP/1.1 302 Found
        // Location: http://www.example.org/index.php
        String value = msg.getResponseHeader().getHeader(HttpFieldsNames.LOCATION);
        if (checkPayload(value)) {
            return RedirectType.LOCATION_HEADER;
        }

        // (2) Check if redirection by "Refresh" header
        // http://en.wikipedia.org/wiki/URL_redirection
        // HTTP/1.1 200 ok
        // Refresh: 0; url=http://www.example.com/
        value = msg.getResponseHeader().getHeader(HttpFieldsNames.REFRESH);
        if (value != null) {
            // Usually redirect content is configured with a delay
            // so extract the url component
            value = getRefreshUrl(value);

            if (checkPayload(value)) {
                return RedirectType.REFRESH_HEADER;
            }
        }

        // (3) Check if redirection occurs by "Meta" content header
        // http://code.google.com/p/html5security/wiki/RedirectionMethods
        // <meta http-equiv="location" content="URL=http://evil.com" />
        // <meta http-equiv="refresh" content="0;url=http://evil.com/" />
        String content = msg.getResponseBody().toString();
        Source htmlSrc = new Source(content);
        List<Element> metaElements = htmlSrc.getAllElements(HTMLElementName.META);
        for (Element el : metaElements) {

            value = el.getAttributeValue("http-equiv");

            if (value != null) {
                if (value.equalsIgnoreCase(HttpFieldsNames.LOCATION)) {
                    // Get the content attribute value
                    value = getLocationUrl(el.getAttributeValue("content"));

                    // Check if the payload is inside the location attribute
                    if (checkPayload(value)) {
                        return RedirectType.LOCATION_META;
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
                        if (checkPayload(value)) {
                            return RedirectType.REFRESH_META;
                        }
                    }
                }
            }
        }

        // (4) Check if redirection occurs by Base Tag
        // http://code.google.com/p/html5security/wiki/RedirectionMethods
        // <base href="http://evil.com/" />

        // (5) Check if redirection occurs by Javascript
        // http://code.google.com/p/html5security/wiki/RedirectionMethods
        if (StringUtils.indexOfIgnoreCase(content, payload) != -1) {
            List<Element> jsElements = htmlSrc.getAllElements(HTMLElementName.SCRIPT);

            for (Element el : jsElements) {
                value = el.getContent().toString();

                if (isRedirectPresent(JS_LOCATION_PATT, value)) {
                    return RedirectType.JAVASCRIPT;
                }

                if (isRedirectPresent(JS_LOCATION_EXTENDED_PATT, value)) {
                    return RedirectType.JAVASCRIPT;
                }

                if (isRedirectPresent(JS_WINDOW_PATT, value)) {
                    return RedirectType.JAVASCRIPT;
                }
            }
        }

        return RedirectType.NONE;
    }

    private static boolean isRedirectPresent(Pattern pattern, String value) {
        Matcher matcher = pattern.matcher(value);
        if (!matcher.find()) {
            return false;
        }
        Set<String> extractedComments = extractJsComments(value);
        String valueWithoutComments = value;
        for (String comment : extractedComments) {
            valueWithoutComments = valueWithoutComments.replace(comment, "");
        }

        matcher = pattern.matcher(valueWithoutComments);
        return matcher.find()
                && StringUtils.startsWithIgnoreCase(matcher.group(1), HttpHeader.HTTP);
    }

    private enum State {
        NORMAL,
        SLASH,
        LINE_COMMENT,
        BLOCK_COMMENT,
        STRING_SINGLE,
        STRING_DOUBLE,
        TEMPLATE,
        TEMPLATE_EXPR
    }

    /** Visibility increased for unit testing purposes only */
    protected static Set<String> extractJsComments(String code) {
        Set<String> comments = new LinkedHashSet<>();
        StringBuilder current = null;

        Deque<State> stateStack = new ArrayDeque<>();
        Deque<Integer> exprDepthStack = new ArrayDeque<>(); // for nested ${...}

        State state = State.NORMAL;
        int i = 0;
        final int n = code.length();

        while (i < n) {
            char c = code.charAt(i);

            switch (state) {
                case NORMAL:
                    if (c == '"') {
                        stateStack.push(state);
                        state = State.STRING_DOUBLE;
                        i++;
                    } else if (c == '\'') {
                        stateStack.push(state);
                        state = State.STRING_SINGLE;
                        i++;
                    } else if (c == '`') {
                        stateStack.push(state);
                        state = State.TEMPLATE;
                        i++;
                    } else if (c == '/') {
                        state = State.SLASH;
                        i++;
                    } else {
                        i++;
                    }
                    break;

                case SLASH:
                    if (i >= n) {
                        state = State.NORMAL;
                        break;
                    }
                    char d = code.charAt(i);
                    if (d == '/') {
                        current = new StringBuilder("//");
                        state = State.LINE_COMMENT;
                        i++;
                    } else if (d == '*') {
                        current = new StringBuilder("/*");
                        state = State.BLOCK_COMMENT;
                        i++;
                    } else {
                        state = State.NORMAL;
                    }
                    break;

                case LINE_COMMENT:
                    if (i < n) {
                        char ch = code.charAt(i);
                        current.append(ch);
                        i++;
                        if (isLineTerminator(ch)) {
                            comments.add(current.toString());
                            current = null;
                            state = State.NORMAL;
                        }
                    } else {
                        // EOF inside line comment
                        comments.add(current.toString());
                        current = null;
                        state = State.NORMAL;
                    }
                    break;

                case BLOCK_COMMENT:
                    if (i < n) {
                        char ch = code.charAt(i);
                        current.append(ch);
                        if (ch == '*' && i + 1 < n && code.charAt(i + 1) == '/') {
                            current.append('/');
                            i += 2;
                            comments.add(current.toString());
                            current = null;
                            state = State.NORMAL;
                        } else {
                            i++;
                        }
                    } else {
                        // EOF inside block comment
                        comments.add(current.toString());
                        current = null;
                        state = State.NORMAL;
                    }
                    break;

                case STRING_DOUBLE:
                    if (c == '\\') {
                        i = consumeJsEscape(code, i) + 1;
                    } else if (c == '"') {
                        state = stateStack.pop();
                        i++;
                    } else {
                        i++;
                    }
                    break;

                case STRING_SINGLE:
                    if (c == '\\') {
                        i = consumeJsEscape(code, i) + 1;
                    } else if (c == '\'') {
                        state = stateStack.pop();
                        i++;
                    } else {
                        i++;
                    }
                    break;

                case TEMPLATE:
                    if (c == '\\') {
                        i = consumeJsEscape(code, i) + 1;
                    } else if (c == '`') {
                        state = stateStack.pop();
                        i++;
                    } else if (c == '$' && i + 1 < n && code.charAt(i + 1) == '{') {
                        stateStack.push(state);
                        exprDepthStack.push(1); // start of template expression
                        state = State.TEMPLATE_EXPR;
                        i += 2;
                    } else {
                        i++;
                    }
                    break;

                case TEMPLATE_EXPR:
                    if (c == '"') {
                        stateStack.push(state);
                        state = State.STRING_DOUBLE;
                        i++;
                    } else if (c == '\'') {
                        stateStack.push(state);
                        state = State.STRING_SINGLE;
                        i++;
                    } else if (c == '`') {
                        stateStack.push(state);
                        state = State.TEMPLATE;
                        i++;
                    } else if (c == '{') {
                        exprDepthStack.push(exprDepthStack.pop() + 1);
                        i++;
                    } else if (c == '}') {
                        int depth = exprDepthStack.pop() - 1;
                        if (depth == 0) {
                            state = stateStack.pop();
                        } else {
                            exprDepthStack.push(depth);
                        }
                        i++;
                    } else if (c == '/') {
                        state = State.SLASH;
                        i++;
                    } else {
                        i++;
                    }
                    break;
            }
        }

        // EOF handling: finalize any pending comment regardless of state
        if (current != null) {
            comments.add(current.toString());
        }

        return comments;
    }

    private static int consumeJsEscape(String s, int backslash) {
        int n = s.length();
        int i = backslash;
        if (i + 1 >= n) return i;

        char e = s.charAt(i + 1);

        if (isLineTerminator(e)) {
            if (e == '\r' && i + 2 < n && s.charAt(i + 2) == '\n') return i + 2;
            return i + 1;
        }

        if (e == 'x' || e == 'X') {
            int j = i + 2, count = 0;
            while (j < n && count < 2 && isHexDigit(s.charAt(j))) {
                j++;
                count++;
            }
            return j - 1;
        }

        if (e == 'u' || e == 'U') {
            int j = i + 2;
            if (j < n && s.charAt(j) == '{') {
                j++;
                while (j < n && isHexDigit(s.charAt(j))) j++;
                if (j < n && s.charAt(j) == '}') j++;
                return j - 1;
            } else {
                int count = 0;
                while (j < n && count < 4 && isHexDigit(s.charAt(j))) {
                    j++;
                    count++;
                }
                return j - 1;
            }
        }

        if (e >= '0' && e <= '7') {
            int j = i + 1, count = 0;
            while (j < n && count < 3 && s.charAt(j) >= '0' && s.charAt(j) <= '7') {
                j++;
                count++;
            }
            return j - 1;
        }

        return i + 1;
    }

    private static boolean isHexDigit(char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }

    private static boolean isLineTerminator(char c) {
        return c == '\n' || c == '\r' || c == '\u2028' || c == '\u2029';
    }

    @Override
    public int getRisk() {
        return Alert.RISK_HIGH;
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    @Override
    public int getCweId() {
        return 601;
    }

    @Override
    public int getWascId() {
        return 38;
    }

    @Override
    public List<Alert> getExampleAlerts() {
        List<Alert> alerts = new ArrayList<>();
        String param = "destination";
        String site = "http://3412390346190766618.owasp.org";
        alerts.add(buildAlert(param, site, RedirectType.LOCATION_HEADER, site, null).build());
        alerts.add(
                buildAlert(
                                param,
                                "5;URL='%s'".formatted(site),
                                RedirectType.REFRESH_HEADER,
                                site,
                                null)
                        .build());
        alerts.add(
                buildAlert(
                                param,
                                "5;URL='%s'".formatted(site),
                                RedirectType.REFRESH_META,
                                site,
                                null)
                        .build());
        alerts.add(buildAlert(param, site, RedirectType.JAVASCRIPT, site, null).build());
        return alerts;
    }
}
