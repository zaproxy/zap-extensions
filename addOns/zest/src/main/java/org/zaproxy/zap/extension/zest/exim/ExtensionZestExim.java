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
package org.zaproxy.zap.extension.zest.exim;

import java.util.List;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.addon.exim.ExtensionExim;
import org.zaproxy.zap.extension.zest.ExtensionZest;

/**
 * A sub-extension of Zest that adds Zest script export and import support to the Import/Export
 * add-on. Only loaded when the Import/Export add-on is installed.
 */
public class ExtensionZestExim extends ExtensionAdaptor {

    public static final String NAME = "ExtensionZestExim";

    private static final List<Class<? extends Extension>> DEPENDENCIES =
            List.of(ExtensionExim.class, ExtensionZest.class);

    public ExtensionZestExim() {
        super(NAME);
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        ExtensionExim extExim =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionExim.class);
        ExtensionZest extZest =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionZest.class);
        extExim.registerExporterType(
                "zest", new ZestExporter(extZest), Constant.messages.getString("zest.exim.type"));

        if (hasView()) {
            extensionHook.getHookMenu().addImportMenuItem(new MenuImportZest());
        }
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        Control.getSingleton()
                .getExtensionLoader()
                .getExtension(ExtensionExim.class)
                .unregisterExporterType("zest");
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return DEPENDENCIES;
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("zest.exim.desc");
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString("zest.exim.name");
    }
}
