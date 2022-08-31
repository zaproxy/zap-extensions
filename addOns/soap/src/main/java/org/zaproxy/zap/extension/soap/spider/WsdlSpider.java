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

import org.zaproxy.addon.spider.parser.ParseContext;
import org.zaproxy.addon.spider.parser.SpiderParser;
import org.zaproxy.zap.extension.soap.WSDLCustomParser;
import org.zaproxy.zap.extension.soap.WsdlSpiderHelper;

public class WsdlSpider extends SpiderParser {

    private final WSDLCustomParser parser;

    public WsdlSpider(WSDLCustomParser parser) {
        this.parser = parser;
    }

    @Override
    public boolean parseResource(ParseContext ctx) {
        return WsdlSpiderHelper.parseWsdl(parser, ctx.getHttpMessage());
    }

    @Override
    public boolean canParseResource(ParseContext ctx, boolean wasAlreadyConsumed) {
        return WsdlSpiderHelper.canParseMessage(ctx.getHttpMessage());
    }
}
