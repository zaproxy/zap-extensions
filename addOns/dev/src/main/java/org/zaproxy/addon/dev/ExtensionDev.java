/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.zaproxy.addon.dev;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.addon.dev.error.LoggedErrorsHandler;
import org.zaproxy.addon.network.ExtensionNetwork;
import org.zaproxy.zap.view.ZapMenuItem;

public class ExtensionDev extends ExtensionAdaptor {

    public static final String NAME = "ExtensionDev";

    protected static final String PREFIX = "dev";

    protected static final String DIRECTORY_NAME = "dev-add-on";

    private final LoggedErrorsHandler loggedErrorsHandler;

    private TestProxyServer tutorialServer;

    private DevParam devParam;

    public ExtensionDev() {
        super(NAME);

        loggedErrorsHandler = new LoggedErrorsHandler();
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        loggedErrorsHandler.hook(extensionHook);

        extensionHook.addOptionsParamSet(this.getDevParam());

        if (Constant.isDevMode()) {
            tutorialServer =
                    new TestProxyServer(
                            this,
                            Control.getSingleton()
                                    .getExtensionLoader()
                                    .getExtension(ExtensionNetwork.class));
            extensionHook.addApiImplementor(new DevApi());
        }

        if (hasView()
                && org.zaproxy.zap.extension.log4j.ExtensionLog4j.class.getAnnotation(
                                Deprecated.class)
                        != null) {
            ZapMenuItem menuGarbageCollect = new ZapMenuItem("dev.tools.menu.gc");
            menuGarbageCollect.addActionListener(e -> Runtime.getRuntime().gc());
            extensionHook.getHookMenu().addToolsMenuItem(menuGarbageCollect);
        }
    }

    public DevParam getDevParam() {
        if (devParam == null) {
            devParam = new DevParam();
        }
        return devParam;
    }

    @Override
    public void optionsLoaded() {
        if (tutorialServer != null) {
            tutorialServer.start();
        }
    }

    @Override
    public void unload() {
        if (tutorialServer != null) {
            tutorialServer.stop();
        }

        loggedErrorsHandler.unload();
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(PREFIX + ".desc");
    }
}
