/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2019 The ZAP Development Team
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
package org.zaproxy.zap.extension.quickstart.ajaxspider;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.quickstart.ExtensionQuickStart;
import org.zaproxy.zap.extension.selenium.ExtensionSelenium;
import org.zaproxy.zap.extension.spiderAjax.ExtensionAjax;

/**
 * Provides the option to use the Ajax Spider when running a quick scan. This is a separate
 * extension so that the main extension still loads if the Ajax Spider is not installed.
 */
public class ExtensionQuickStartAjaxSpider extends ExtensionAdaptor {

    public static final String NAME = "ExtensionQuickStartAjaxSpider";

    private static final List<Class<? extends Extension>> DEPENDENCIES;

    private AjaxSpiderExplorer ase;

    static {
        List<Class<? extends Extension>> dependencies = new ArrayList<>(2);
        dependencies.add(ExtensionAjax.class);
        dependencies.add(ExtensionSelenium.class);
        DEPENDENCIES = Collections.unmodifiableList(dependencies);
    }

    public ExtensionQuickStartAjaxSpider() {
        super(NAME);
    }

    @Override
    public boolean supportsDb(String type) {
        return true;
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        if (getView() != null) {
            this.ase = new AjaxSpiderExplorer(this);
            this.getExtQuickStart().addPlugableSpider(ase);
        }
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        if (getView() != null) {
            this.getExtQuickStart().removePlugableSpider(ase);
        }
    }

    @Override
    public void optionsLoaded() {
        super.optionsLoaded();
        if (View.isInitialised()) {
            this.ase.optionsLoaded(getExtQuickStart().getQuickStartParam());
        }
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return DEPENDENCIES;
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("quickstart.ajaxspider.desc");
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString("quickstart.ajaxspider.name");
    }

    public ExtensionQuickStart getExtQuickStart() {
        return Control.getSingleton().getExtensionLoader().getExtension(ExtensionQuickStart.class);
    }

    public ExtensionSelenium getExtSelenium() {
        return Control.getSingleton().getExtensionLoader().getExtension(ExtensionSelenium.class);
    }
}
