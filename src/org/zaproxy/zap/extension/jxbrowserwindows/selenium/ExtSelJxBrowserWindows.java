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
package org.zaproxy.zap.extension.jxbrowserwindows.selenium;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.zap.extension.selenium.ExtensionSelenium;

/**
 * An {@link org.parosproxy.paros.extension.Extension Extension} that installs a {@link JxBrowserProvider}, if in Windows.
 */
public class ExtSelJxBrowserWindows extends ExtensionAdaptor {

    public static final String NAME = "ExtSelJxBrowserWindows";

    private static final List<Class<? extends Extension>> DEPENDENCIES;

    static {
        List<Class<? extends Extension>> dependencies = new ArrayList<>(1);
        dependencies.add(ExtensionSelenium.class);
        DEPENDENCIES = Collections.unmodifiableList(dependencies);
    }

    private JxBrowserProvider webDriverProvider;

    public ExtSelJxBrowserWindows() {
        super(NAME);
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        if (Constant.isWindows()) {
            webDriverProvider = new JxBrowserProvider();

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
