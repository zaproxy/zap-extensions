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

import net.htmlparser.jericho.Source;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.spider.internal.Adapters;

public class AddOnToCoreSpiderParser extends org.zaproxy.zap.spider.parser.SpiderParser {

    private final SpiderParser parser;

    public AddOnToCoreSpiderParser(SpiderParser parser) {
        this.parser = parser;
    }

    @Override
    public void addSpiderParserListener(
            org.zaproxy.zap.spider.parser.SpiderParserListener listener) {
        parser.addSpiderParserListener(Adapters.coreToAddOn(listener));
    }

    @Override
    public void removeSpiderParserListener(
            org.zaproxy.zap.spider.parser.SpiderParserListener listener) {
        parser.removeSpiderParserListener(Adapters.coreToAddOn(listener));
    }

    @Override
    protected void notifyListenersResourceFound(
            org.zaproxy.zap.spider.parser.SpiderResourceFound resourceFound) {
        parser.notifyListenersResourceFound(Adapters.coreToAddOn(resourceFound));
    }

    @Override
    public boolean parseResource(HttpMessage message, Source source, int depth) {
        return parser.parseResource(message, source, depth);
    }

    @Override
    public boolean canParseResource(HttpMessage message, String path, boolean wasAlreadyConsumed) {
        return parser.canParseResource(message, path, wasAlreadyConsumed);
    }

    @Override
    public int hashCode() {
        return parser.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof AddOnToCoreSpiderParser)) {
            return false;
        }
        return parser.equals(((AddOnToCoreSpiderParser) obj).parser);
    }
}
