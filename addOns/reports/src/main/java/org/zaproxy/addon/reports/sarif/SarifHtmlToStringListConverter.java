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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SarifHtmlToStringListConverter {

    /** Shared default instance */
    public static final SarifHtmlToStringListConverter DEFAULT =
            new SarifHtmlToStringListConverter();

    private static final Pattern PATTERN_HTML_P_CONTENT = Pattern.compile("<p>([^<]+)<\\/p>");

    /**
     * Converts given HTML content to a simple string list. Currently supported:
     *
     * <ul>
     *   <li>Element content inside &lt;p&gt; tags will be used as a trimmed string and added as a
     *       list element
     * </ul>
     *
     * If supported HTML elements are detected, those element content will be added to resulting
     * list and all other content will be just ignored! If not at least one HTML element was
     * detected, the given content will be treated as plain text and just splitted to dedicated
     * lines. Each line will be added as list element then.
     *
     * @param content can be either HTML or plain text
     * @return list containing plain text elements
     */
    public List<String> convertToList(String content) {
        if (content == null || content.trim().isEmpty()) {
            return Collections.emptyList();
        }

        List<String> list = new ArrayList<>();

        Matcher matcher = PATTERN_HTML_P_CONTENT.matcher(content);
        while (matcher.find()) {
            String group = matcher.group(1);
            list.add(group.trim());
        }

        if (list.isEmpty()) {
            // happens when no HTML parts/only one entry
            String[] lines = content.split("\n");
            for (String line : lines) {
                list.add(line);
            }
        }

        return list;
    }
}
