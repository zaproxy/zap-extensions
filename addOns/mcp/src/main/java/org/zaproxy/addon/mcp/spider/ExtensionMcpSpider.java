/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.addon.mcp.spider;

import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.addon.mcp.ExtensionMcp;
import org.zaproxy.addon.spider.ExtensionSpider2;
import org.zaproxy.addon.spider.parser.SpiderParser;

public class ExtensionMcpSpider extends ExtensionAdaptor {

    public static final String NAME = "ExtensionMcpSpider";
    private static final Logger LOGGER = LogManager.getLogger(ExtensionMcpSpider.class);
    private static final List<Class<? extends Extension>> DEPENDENCIES =
            List.of(ExtensionSpider2.class, ExtensionMcp.class);

    private SpiderParser customSpider;

    public ExtensionMcpSpider() {
        super(NAME);
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        customSpider = new McpSpider();
        getSpiderExt().addCustomParser(customSpider);
        LOGGER.debug("Added custom MCP spider.");
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        getSpiderExt().removeCustomParser(customSpider);
        LOGGER.debug("Removed custom MCP spider.");
    }

    private ExtensionSpider2 getSpiderExt() {
        return Control.getSingleton().getExtensionLoader().getExtension(ExtensionSpider2.class);
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("mcp.spider.desc");
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString("mcp.spider.name");
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return DEPENDENCIES;
    }
}
