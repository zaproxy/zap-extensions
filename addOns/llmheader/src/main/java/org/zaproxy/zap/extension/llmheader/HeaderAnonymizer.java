/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
package org.zaproxy.zap.extension.llmheader;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.parosproxy.paros.network.HttpHeader;

public class HeaderAnonymizer {

    private static final Set<String> SENSITIVE_HEADERS =
            new HashSet<>(
                    Arrays.asList(
                            "Authorization",
                            "Cookie",
                            "Set-Cookie",
                            "Proxy-Authorization",
                            "X-Api-Key",
                            "Forwarded",
                            "X-Forwarded-For"));

    public static Map<String, String> anonymize(HttpHeader header, boolean enabled) {
        Map<String, String> headers = new HashMap<>();
        String headerString = header.toString();
        String[] lines = headerString.split("\\r\\n");

        // Skip the first line (Request/Response line)
        for (int i = 1; i < lines.length; i++) {
            String line = lines[i];
            if (line.isEmpty()) continue;

            int colonIndex = line.indexOf(':');
            if (colonIndex > 0) {
                String name = line.substring(0, colonIndex).trim();
                String value = line.substring(colonIndex + 1).trim();

                if (enabled && SENSITIVE_HEADERS.stream().anyMatch(h -> h.equalsIgnoreCase(name))) {
                    headers.put(name, "[REDACTED]");
                } else {
                    headers.put(name, value);
                }
            }
        }
        return headers;
    }
}
