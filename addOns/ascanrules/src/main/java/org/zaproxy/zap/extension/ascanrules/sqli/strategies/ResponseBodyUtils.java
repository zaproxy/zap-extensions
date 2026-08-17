/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.zap.extension.ascanrules.sqli.strategies;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import org.apache.commons.lang3.StringEscapeUtils;

/** Utilities for comparing response bodies in SQL injection detection strategies. */
public final class ResponseBodyUtils {

    private ResponseBodyUtils() {}

    /**
     * Removes all occurrences of {@code needle} from {@code text}, case-insensitive.
     *
     * @param text the text to strip from
     * @param needle the substring to remove
     * @return text with needle removed, or empty string if text is null
     */
    static String strip(String text, String needle) {
        if (text == null || text.isEmpty() || needle == null || needle.isEmpty()) {
            return text == null ? "" : text;
        }
        return text.replaceAll("(?i)" + java.util.regex.Pattern.quote(needle), "");
    }

    /**
     * Removes all occurrences of the given patterns from {@code text}, stripping multiple encoding
     * forms: literal, URL-encoded, HTML-entity-encoded (single and double), and XML-escaped.
     *
     * <p>This mirrors baseline rule 40018's {@code stripOff} / {@code stripOffOriginalAndAttackParam}
     * logic, which strips the injected value in all its possible encoded forms to avoid the payload
     * itself skewing response-body comparisons.
     *
     * @param text the response body to strip from
     * @param patterns the substrings to remove (e.g., original param value, attack payload)
     * @return text with all patterns and their encoded forms removed
     */
    @SuppressWarnings("deprecation")
    public static String stripAllEncodedForms(String text, String... patterns) {
        if (text == null || text.isEmpty()) {
            return text == null ? "" : text;
        }

        String result = text;
        for (String pattern : patterns) {
            if (pattern == null || pattern.isEmpty()) {
                continue;
            }

            // Strip the literal pattern
            result = result.replaceAll("\\Q" + pattern + "\\E", "");

            // Strip URL-encoded form (UTF-8)
            String urlEncoded = URLEncoder.encode(pattern, StandardCharsets.UTF_8);
            result = result.replaceAll("\\Q" + urlEncoded + "\\E", "");

            // Strip HTML-entity-encoded form
            String htmlEncoded = StringEscapeUtils.escapeHtml4(pattern);
            result = result.replaceAll("\\Q" + htmlEncoded + "\\E", "");

            // Strip HTML-entity-encoded form of the URL-encoded pattern (double encoding)
            String doubleEncoded = StringEscapeUtils.escapeHtml4(urlEncoded);
            result = result.replaceAll("\\Q" + doubleEncoded + "\\E", "");

            // Strip XML-escaped form (preferred over XML 11 per baseline comment)
            String xmlEscaped = StringEscapeUtils.escapeXml10(pattern);
            result = result.replaceAll("\\Q" + xmlEscaped + "\\E", "");
        }

        return result;
    }
}
