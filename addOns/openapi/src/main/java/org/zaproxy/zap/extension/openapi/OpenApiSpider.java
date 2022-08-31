/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2017 The ZAP Development Team
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
package org.zaproxy.zap.extension.openapi;

import java.util.function.Supplier;
import net.htmlparser.jericho.Source;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.openapi.spider.OpenApiSpiderFunctionality;
import org.zaproxy.zap.model.ValueGenerator;
import org.zaproxy.zap.spider.parser.SpiderParser;

public class OpenApiSpider extends SpiderParser {

    private OpenApiSpiderFunctionality func = null;

    public OpenApiSpider(Supplier<ValueGenerator> valueGeneratorSupplier) {
        func = new OpenApiSpiderFunctionality(valueGeneratorSupplier);
    }

    @Override
    public boolean parseResource(HttpMessage message, Source source, int depth) {
        return func.parseResource(message);
    }

    @Override
    public boolean canParseResource(HttpMessage message, String path, boolean wasAlreadyConsumed) {
        return func.canParseResource(message);
    }
}
