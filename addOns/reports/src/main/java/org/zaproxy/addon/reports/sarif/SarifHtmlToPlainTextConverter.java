/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.addon.reports.sarif;

import java.util.regex.Pattern;

public class SarifHtmlToPlainTextConverter {

    private static final Pattern PATTERN_XML_START_OR_END_TAG = Pattern.compile("<[a-zA-Z-/]*>");
    private static final Pattern PATTERN_HTML_P_END = Pattern.compile("</p>");
    private static final Pattern PATTERN_HTML_BR = Pattern.compile("<br>|<br/>");

    /** Shared default instance */
    public static final SarifHtmlToPlainTextConverter DEFAULT = new SarifHtmlToPlainTextConverter();

    /**
     * Converts given HTML content to plain text. HTML Tags "br" and "p" will be changed to new
     * lines, all other tags are just removed.
     *
     * @param html is the given HTML content which shall be converted to plain text
     * @return plain text
     */
    public String convertToPlainText(String html) {
        if (html == null) {
            return null;
        }
        String result = html;

        result = PATTERN_HTML_P_END.matcher(result).replaceAll("\n");
        result = PATTERN_HTML_BR.matcher(result).replaceAll("\n");
        result = PATTERN_XML_START_OR_END_TAG.matcher(result).replaceAll("");

        return result;
    }
}
