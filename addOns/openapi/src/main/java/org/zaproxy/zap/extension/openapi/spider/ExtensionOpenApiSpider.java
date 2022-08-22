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
package org.zaproxy.zap.extension.openapi.spider;

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
import org.zaproxy.addon.spider.ExtensionSpider2;
import org.zaproxy.addon.spider.parser.SpiderParser;
import org.zaproxy.zap.extension.openapi.ExtensionOpenApi;

public class ExtensionOpenApiSpider extends ExtensionAdaptor {

    public static final String NAME = "ExtensionOpenApiSpider";
    private static final Logger LOGGER = LogManager.getLogger(ExtensionOpenApiSpider.class);
    private static final List<Class<? extends Extension>> DEPENDENCIES =
            Collections.unmodifiableList(
                    Arrays.asList(ExtensionSpider2.class, ExtensionOpenApi.class));

    private SpiderParser customSpider;

    public ExtensionOpenApiSpider() {
        super(NAME);
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        ExtensionSpider2 spider =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionSpider2.class);
        ExtensionOpenApi extOpenApi =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionOpenApi.class);
        customSpider = new OpenApiSpider(extOpenApi::getValueGenerator);
        spider.addCustomParser(customSpider);
        LOGGER.debug("Added custom Open API spider.");
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        super.unload();
        ExtensionSpider2 spider =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionSpider2.class);
        spider.removeCustomParser(customSpider);
        LOGGER.debug("Removed custom Open API spider.");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("openapi.spider.desc");
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString("openapi.spider.name");
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return DEPENDENCIES;
    }
}
