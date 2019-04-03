/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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
package org.zaproxy.zap.extension.jxbrowserwindows64.selenium;

import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.zap.extension.jxbrowser.Utils;
import org.zaproxy.zap.extension.selenium.ExtensionSelenium;

/**
 * An {@link org.parosproxy.paros.extension.Extension Extension} that installs a {@link JxBrowserProvider}, if in Windows 64bits.
 */
public class ExtSelJxBrowserWindows64 extends ExtensionAdaptor {

    public static final String NAME = "ExtSelJxBrowserWindows64";

    private static final List<Class<? extends Extension>> DEPENDENCIES;

    static {
        List<Class<? extends Extension>> dependencies = new ArrayList<>(1);
        dependencies.add(ExtensionSelenium.class);
        DEPENDENCIES = Collections.unmodifiableList(dependencies);
    }

    private JxBrowserProvider webDriverProvider;

    public ExtSelJxBrowserWindows64() {
        super(NAME);
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        if (Constant.isWindows() && Utils.isOs64Bits()) {
            webDriverProvider = new JxBrowserProvider(
                    Paths.get(Constant.getZapHome(), "jxbrowser/webdriver/windows/chromedriver.exe"));

            ExtensionSelenium extSelenium = Control.getSingleton().getExtensionLoader().getExtension(ExtensionSelenium.class);
            extSelenium.addWebDriverProvider(webDriverProvider);
        }
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        super.unload();

        if (webDriverProvider != null) {
            ExtensionSelenium extSelenium = Control.getSingleton().getExtensionLoader().getExtension(ExtensionSelenium.class);
            extSelenium.removeWebDriverProvider(webDriverProvider);
        }
    }

    @Override
    public String getAuthor() {
        return Constant.ZAP_TEAM;
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return DEPENDENCIES;
    }
}
