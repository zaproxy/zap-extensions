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
package org.zaproxy.addon.spider;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.zap.extension.spider.ExtensionSpider;
import org.zaproxy.zap.spider.parser.SpiderParser;

public class ExtensionSpider2 extends ExtensionAdaptor {
    public static final String NAME = "ExtensionSpider2";
    private static final Logger LOGGER = LogManager.getLogger(ExtensionSpider2.class);
    private static final List<Class<? extends Extension>> DEPENDENCIES =
            Collections.unmodifiableList(Arrays.asList(ExtensionSpider.class));

    private SpiderParser svgHrefSpider;

    public ExtensionSpider2() {
        super(NAME);
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        ExtensionSpider spider = getExtensionSpider();
        svgHrefSpider = new SvgHrefSpider();
        spider.addCustomParser(svgHrefSpider);
        LOGGER.debug("Added custom SVG HREF spider.");
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return DEPENDENCIES;
    }

    @Override
    public void unload() {
        getExtensionSpider().removeCustomParser(svgHrefSpider);
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("spider.addon.desc");
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString("spider.addon.name");
    }

    private ExtensionSpider getExtensionSpider() {
        return Control.getSingleton().getExtensionLoader().getExtension(ExtensionSpider.class);
    }
}
