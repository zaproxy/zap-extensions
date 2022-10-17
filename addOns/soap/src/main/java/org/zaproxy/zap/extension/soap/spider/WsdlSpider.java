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
package org.zaproxy.zap.extension.soap.spider;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.spider.parser.ParseContext;
import org.zaproxy.addon.spider.parser.SpiderParser;
import org.zaproxy.zap.extension.soap.WSDLCustomParser;

public class WsdlSpider extends SpiderParser {

    private final WSDLCustomParser parser;

    public WsdlSpider(WSDLCustomParser parser) {
        this.parser = parser;
    }

    @Override
    public boolean parseResource(ParseContext ctx) {
        if (!canParseMessage(ctx)) {
            return false;
        }

        String content = ctx.getHttpMessage().getResponseBody().toString().trim();
        parser.extContentWSDLImport(content, true);
        return true;
    }

    private boolean canParseMessage(ParseContext ctx) {
        HttpMessage message = ctx.getHttpMessage();
        if (canParseResource(ctx, false)
                || message.getResponseHeader().hasContentType("text/xml", "application/wsdl+xml")) {
            String content = message.getResponseBody().toString();
            if (parser.canBeWSDLparsed(content)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public boolean canParseResource(ParseContext ctx, boolean wasAlreadyConsumed) {
        return ctx.getHttpMessage().getRequestHeader().getURI().toString().endsWith(".wsdl");
    }
}
