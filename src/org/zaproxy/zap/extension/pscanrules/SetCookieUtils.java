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

/**
 * Utility class to extract/parse/check Set-Cookie header values.
 */
class SetCookieUtils {

    private static final int NOT_FOUND = -1;

    private SetCookieUtils() {
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
}
