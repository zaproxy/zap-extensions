/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
import org.parosproxy.paros.network.HttpMessage;

/**
 * The Class SpiderHttpHeaderParser is used for parsing of HTTP headers that can include URLs.
 *
 * @see SpiderRedirectParser
 */
public class SpiderHttpHeaderParser extends SpiderParser {

    @Override
    public boolean parseResource(ParseContext ctx) {
        HttpMessage message = ctx.getHttpMessage();

        // Content-location header
        // TODO replace when next core version available HttpHeader.CONTENT_LOCATION
        String location = message.getResponseHeader().getHeader("Content-Location");
        if (location != null && !location.isEmpty()) {
            processUrl(ctx, location);
        }
        // Refresh header
        // TODO replace when next core version available HttpHeader.REFRESH
        String refresh = message.getResponseHeader().getHeader("Refresh");
        if (refresh != null && !refresh.isEmpty()) {
            Matcher matcher = SpiderHtmlParser.URL_PATTERN.matcher(refresh);
            if (matcher.find()) {
                String url = matcher.group(1);
                processUrl(ctx, url);
            }
        }

        // Link header - potentially multiple absolute or relative URLs in < >
        // TODO replace when next core version available HttpHeader.LINK
        String link = message.getResponseHeader().getHeader("Link");
        if (link != null && !link.isEmpty()) {
            int offset = 0;
            while (true) {
                int i = link.indexOf("<", offset);
                if (i < 0) {
                    break;
                }
                int j = link.indexOf(">", i);
                if (j < 0) {
                    break;
                }
                processUrl(ctx, link.substring(i + 1, j));
                offset = j;
            }
        }
        // We do not consider the message fully parsed
        return false;
    }

    @Override
    public boolean canParseResource(ParseContext ctx, boolean wasAlreadyParsed) {
        return true;
    }
}
