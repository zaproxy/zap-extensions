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
package org.zaproxy.addon.exim.automation;

import java.util.List;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.addon.automation.ExtensionAutomation;
import org.zaproxy.addon.exim.ExtensionExim;

public class ExtensionEximAutomation extends ExtensionAdaptor {

    public static final String NAME = "ExtensionEximAutomation";

    private static final List<Class<? extends Extension>> DEPENDENCIES =
            List.of(ExtensionExim.class, ExtensionAutomation.class);

    private ImportJob importJob;

    public ExtensionEximAutomation() {
        super(NAME);
    }

    @Override
    public boolean supportsDb(String type) {
        return true;
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);
        ExtensionAutomation extAuto =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionAutomation.class);
        importJob = new ImportJob();
        extAuto.registerAutomationJob(importJob);
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        ExtensionAutomation extAuto =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionAutomation.class);

        extAuto.unregisterAutomationJob(importJob);
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return DEPENDENCIES;
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("exim.automation.desc");
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString("exim.automation.name");
    }
}
