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
package org.zaproxy.addon.client.exim;

import java.util.List;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.addon.client.ExtensionClientIntegration;
import org.zaproxy.addon.exim.ExporterOptions.Source;
import org.zaproxy.addon.exim.ExtensionExim;

/**
 * A sub-extension of the Client Side Integration add-on that adds Client Map export support to the
 * Import/Export add-on. Only loaded when the Import/Export add-on is installed.
 */
public class ExtensionClientExim extends ExtensionAdaptor {

    public static final String NAME = "ExtensionClientExim";

    private static final List<Class<? extends Extension>> DEPENDENCIES =
            List.of(ExtensionExim.class, ExtensionClientIntegration.class);

    public ExtensionClientExim() {
        super(NAME);
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        ExtensionExim extExim =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionExim.class);
        ExtensionClientIntegration extClient =
                Control.getSingleton()
                        .getExtensionLoader()
                        .getExtension(ExtensionClientIntegration.class);
        extExim.registerSourceExporter(Source.CLIENTMAP, new ClientMapExporter(extClient));
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        ExtensionExim extExim =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionExim.class);
        extExim.unregisterSourceExporter(Source.CLIENTMAP);
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return DEPENDENCIES;
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("client.exim.desc");
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString("client.exim.name");
    }
}
