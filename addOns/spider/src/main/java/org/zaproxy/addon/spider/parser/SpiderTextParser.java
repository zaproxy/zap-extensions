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

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.parosproxy.paros.network.HttpMessage;

/**
 * The Class SpiderTextParser is used for parsing of simple text (non-HTML) files, gathering
 * resource urls from them. For example it is used for parsing CSS, less, javascript files,
 * searching for urls.
 */
public class SpiderTextParser extends SpiderParser {

    /** The Constant urlPattern defining the pattern for an url. */
    private static final Pattern PATTERN_URL =
            Pattern.compile(
                    "\\W(http(s?)://[^\\x00-\\x1f\"'\\s<>#()\\[\\]{}]+)", Pattern.CASE_INSENSITIVE);

    @Override
    public boolean parseResource(ParseContext ctx) {
        getLogger().debug("Parsing a non-HTML text resource.");

        // Use a simple pattern matcher to find urls
        Matcher matcher = PATTERN_URL.matcher(ctx.getHttpMessage().getResponseBody().toString());
        while (matcher.find()) {
            String s = matcher.group(1);
            processUrl(ctx, s);
        }

        return false;
    }

    @Override
    public boolean canParseResource(ParseContext ctx, boolean wasAlreadyConsumed) {
        HttpMessage message = ctx.getHttpMessage();
        // Fall-back parser - if it's a text, non-HTML response which has not already been processed
        return !wasAlreadyConsumed
                && message.getResponseHeader().isText()
                && !message.getResponseHeader().isHtml();
    }
}
