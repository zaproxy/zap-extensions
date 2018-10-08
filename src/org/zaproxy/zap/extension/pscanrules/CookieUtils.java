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

import java.util.HashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.parosproxy.paros.model.Model;
import org.zaproxy.zap.extension.ruleconfig.RuleConfigParam;

/**
 * Utility class to extract/parse/check Set-Cookie header values.
 */
class CookieUtils {

    private static final int NOT_FOUND = -1;

    private CookieUtils() {
        // Utility class.
    }

    /**
     * Tells whether or not the given Set-Cookie header value has an attribute with the given name.
     * <p>
     * If the pair cookie name/value is not conformant (e.g. empty name, missing name/value separator) it returns {@code false}.
     *
     * @param headerValue the value of the header
     * @param attributeName the name of the attribute to check
     * @return {@code true} if the the header has the attribute, {@code false} otherwise
     * @see <a href="https://tools.ietf.org/html/rfc6265#section-5.2">RFC 6265 - Section 5.2</a>
     */
    public static boolean hasAttribute(String headerValue, String attributeName) {
        validateParameterNotNull(headerValue, "headerValue");
        validateParameterNotNull(attributeName, "attributeName");

        if (headerValue.isEmpty() || attributeName.isEmpty()) {
            return false;
        }

        String[] cookieElements = headerValue.split(";");
        if (cookieElements.length == 1 || !isCookieNameValuePairValid(cookieElements[0])) {
            return false;
        }

        for (int i = 1; i < cookieElements.length; i++) {
            String[] attribute = cookieElements[i].split("=", 2);
            if (attributeName.equalsIgnoreCase(attribute[0].trim())) {
                return true;
            }
        }
        return false;
    }

    /**
     * Return the value of the specified attribute in the given Set-Cookie header value, or null if it is not present.
     *
     * @param headerValue the value of the header
     * @param attributeName the name of the attribute
     * @return the attribute value, or null if it is not present
     */
    public static String getAttributeValue(String headerValue, String attributeName) {
        validateParameterNotNull(headerValue, "headerValue");
        validateParameterNotNull(attributeName, "attributeName");

        if (headerValue.isEmpty() || attributeName.isEmpty()) {
            return null;
        }

        String[] cookieElements = headerValue.split(";");
        if (cookieElements.length == 1 || !isCookieNameValuePairValid(cookieElements[0])) {
            return null;
        }

        for (int i = 1; i < cookieElements.length; i++) {
            String[] attribute = cookieElements[i].split("=", 2);
            if (attribute.length > 1 && 
                    attributeName.equalsIgnoreCase(attribute[0].trim())) {
                return attribute[1].trim();
            }
        }
        return null;
    }

    /**
     * Returns the name of the cookie in the given Set-Cookie header value, or null if not found.
     *
     * @param cookieHeaderValue the value of the header value
     * @return the name of the cookie, or null if not found
     */
    public static String getCookieName(String cookieHeaderValue) {
        validateParameterNotNull(cookieHeaderValue, "cookieHeaderValue");

        if (cookieHeaderValue.isEmpty()) {
            return null;
        }

        int nameValuePairIdx = cookieHeaderValue.indexOf('=');
        if (nameValuePairIdx == NOT_FOUND) {
            return null;
        }

        return cookieHeaderValue.substring(0, nameValuePairIdx).trim();
    }

    /**
     * Returns the relevant SetCookie or SetCookie2 line as well as just the cookie name, or null if not found.
     * Typically used for the evidence field in alerts as it does not include the cookie value.
     *
     * @param header the full header
     * @param cookieHeaderValue the value of the header value
     * @return SetCookie(2) plus name of the cookie, or null if not found
     */
    public static String getSetCookiePlusName(String header, String cookieHeaderValue) {
        validateParameterNotNull(header, "header");
        validateParameterNotNull(cookieHeaderValue, "cookieHeaderValue");

        if (header.isEmpty() || cookieHeaderValue.isEmpty()) {
            return null;
        }
        String name = getCookieName(cookieHeaderValue);

        // First find the right line
        Pattern pattern = Pattern.compile("Set-Cookie.*" + Pattern.quote(cookieHeaderValue), Pattern.CASE_INSENSITIVE);
        Matcher matcher = pattern.matcher(header);
        if (matcher.find()) {
            // Found a line that matches
            String match = matcher.group();
            return match.substring(0, match.indexOf(name) + name.length());
        }
        return null;
    }

    private static boolean isCookieNameValuePairValid(String nameValuePair) {
        int nameValuePairIdx = nameValuePair.indexOf('=');
        if (nameValuePairIdx == NOT_FOUND) {
            return false;
        }

        String cookieName = nameValuePair.substring(0, nameValuePairIdx).trim();
        if (cookieName.isEmpty()) {
            return false;
        }

        return true;
    }

    private static void validateParameterNotNull(Object parameter, String name) {
        if (parameter == null) {
            throw new IllegalArgumentException("The parameter " + name + " must not be null.");
        }
    }
    
    public static Set<String> getCookieIgnoreList(Model model) {
        Set<String> ignoreList = new HashSet<String>();
        String ignoreConf = model.getOptionsParam().getConfig().
                getString(RuleConfigParam.RULE_COOKIE_IGNORE_LIST);
        if (ignoreConf != null && ignoreConf.length() > 0) {
            for (String str : ignoreConf.split(",")) {
                String strTrim = str.trim();
                if (strTrim.length() > 0) {
                    ignoreList.add(strTrim);
                }
            }
        }
        return ignoreList;
    }
}
