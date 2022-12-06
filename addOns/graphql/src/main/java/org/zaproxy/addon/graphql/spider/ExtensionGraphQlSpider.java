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
package org.zaproxy.addon.graphql.spider;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.addon.graphql.ExtensionGraphQl;
import org.zaproxy.addon.spider.ExtensionSpider2;
import org.zaproxy.addon.spider.filters.ParseFilter;
import org.zaproxy.addon.spider.parser.SpiderParser;

public class ExtensionGraphQlSpider extends ExtensionAdaptor {

    private static final List<Class<? extends Extension>> DEPENDENCIES =
            Collections.unmodifiableList(
                    Arrays.asList(ExtensionSpider2.class, ExtensionGraphQl.class));

    private SpiderParser spiderParser;
    private ParseFilter parseFilter;

    @Override
    public String getUIName() {
        return Constant.messages.getString("graphql.spider.name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("graphql.spider.desc");
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return DEPENDENCIES;
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        spiderParser = new GraphQlSpider();
        ExtensionSpider2 spider = getExtension(ExtensionSpider2.class);
        spider.addCustomParser(spiderParser);
        parseFilter = new GraphQlParseFilter();
        spider.addCustomParseFilter(parseFilter);
    }

    private static <T extends Extension> T getExtension(Class<T> clazz) {
        return Control.getSingleton().getExtensionLoader().getExtension(clazz);
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        ExtensionSpider2 spider = getExtension(ExtensionSpider2.class);
        spider.removeCustomParser(spiderParser);
        spider.removeCustomParseFilter(parseFilter);
    }
}
