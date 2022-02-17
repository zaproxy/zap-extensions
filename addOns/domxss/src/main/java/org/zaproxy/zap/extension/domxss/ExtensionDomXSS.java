/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2015 The ZAP Development Team
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
package org.zaproxy.zap.extension.domxss;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.PluginFactory;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.addon.network.ExtensionNetwork;
import org.zaproxy.addon.network.server.Server;
import org.zaproxy.zap.extension.selenium.ExtensionSelenium;

/**
 * The extension responsible to add the DOM XSS active scanner.
 *
 * @author psiinon
 */
public class ExtensionDomXSS extends ExtensionAdaptor {

    private static final Logger LOGGER = LogManager.getLogger(ExtensionDomXSS.class);

    private static final List<Class<? extends Extension>> DEPENDENCIES;

    static {
        List<Class<? extends Extension>> dependencies = new ArrayList<>(2);
        dependencies.add(ExtensionNetwork.class);
        dependencies.add(ExtensionSelenium.class);

        DEPENDENCIES = Collections.unmodifiableList(dependencies);
    }

    private DomXssScanRule scanner;

    @Override
    public void init() {
        super.init();

        scanner = new DomXssScanRule();
        scanner.setStatus(getAddOn().getStatus());
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return DEPENDENCIES;
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        DomXssScanRule.extensionNetwork =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionNetwork.class);
        PluginFactory.loadedPlugin(scanner);
    }

    @Override
    public void stop() {
        Server proxy = DomXssScanRule.proxy;
        if (proxy != null) {
            try {
                proxy.stop();
            } catch (IOException e) {
                LOGGER.debug("An error occurred while stopping the proxy.", e);
            }
        }
    }

    @Override
    public void unload() {
        super.unload();

        PluginFactory.unloadedPlugin(scanner);
    }

    @Override
    public String getName() {
        return "ExtensionDomXSS";
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("domxss.desc");
    }

    @Override
    public boolean canUnload() {
        return true;
    }
}
