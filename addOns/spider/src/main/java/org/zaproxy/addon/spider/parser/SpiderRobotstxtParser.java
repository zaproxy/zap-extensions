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
package org.zaproxy.addon.spider.parser;

import java.util.StringTokenizer;
import org.parosproxy.paros.network.HttpMessage;

/** The Class SpiderRobotstxtParser used for parsing Robots.txt files. */
public class SpiderRobotstxtParser extends SpiderParser {

    private static final String COMMENT_TOKEN = "#";

    private static final String PATTERNS_DISALLOW = "(?i)Disallow:.*";
    private static final String PATTERNS_ALLOW = "(?i)Allow:.*";

    private static final int PATTERNS_DISALLOW_LENGTH = 9;
    private static final int PATTERNS_ALLOW_LENGTH = 6;

    /** @throws NullPointerException if {@code message} is null. */
    @Override
    public boolean parseResource(ParseContext ctx) {
        if (!ctx.getSpiderParam().isParseRobotsTxt()) {
            return false;
        }
        getLogger().debug("Parsing a robots.txt resource...");

        HttpMessage message = ctx.getHttpMessage();

        StringTokenizer st = new StringTokenizer(message.getResponseBody().toString(), "\n");
        while (st.hasMoreTokens()) {
            String line = st.nextToken();

            int commentStart = line.indexOf(COMMENT_TOKEN);
            if (commentStart != -1) {
                line = line.substring(0, commentStart);
            }

            // remove HTML markup and clean
            line = line.replaceAll("<[^>]+>", "");
            line = line.trim();

            if (line.isEmpty()) {
                continue;
            }
            getLogger().debug("Processing robots.txt line: {}", line);

            if (line.matches(PATTERNS_DISALLOW)) {
                processPath(ctx, line.substring(PATTERNS_DISALLOW_LENGTH));
            } else if (line.matches(PATTERNS_ALLOW)) {
                processPath(ctx, line.substring(PATTERNS_ALLOW_LENGTH));
            }
        }

        // We consider the message fully parsed, so it doesn't get parsed by 'fallback' parsers
        return true;
    }

    private void processPath(ParseContext ctx, String path) {
        String processedPath = path.trim();
        if (processedPath.endsWith("*")) {
            processedPath = processedPath.substring(0, processedPath.length() - 1).trim();
        }

        if (!processedPath.isEmpty()) {
            processUrl(ctx, processedPath);
        }
    }

    @Override
    public boolean canParseResource(ParseContext ctx, boolean wasAlreadyParsed) {
        // If it's a robots.txt file
        return "/robots.txt".equalsIgnoreCase(ctx.getPath());
    }
}
