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
package org.zaproxy.addon.client.zest;

import java.util.List;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.addon.client.ExtensionClientIntegration;
import org.zaproxy.zap.extension.zest.ExtensionZest;

public class ExtensionClientZest extends ExtensionAdaptor {

    public static final String NAME = "ExtensionClientZest";

    private static final List<Class<? extends Extension>> DEPENDENCIES =
            List.of(ExtensionZest.class, ExtensionClientIntegration.class);

    public ExtensionClientZest() {
        super(NAME);
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);
        ExtensionClientIntegration extClient =
                Control.getSingleton()
                        .getExtensionLoader()
                        .getExtension(ExtensionClientIntegration.class);
        extClient.setClientRecorderHelper(this::addZestStatement);

        ExtensionZest extZest =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionZest.class);

        extZest.setClientHelper(() -> true);
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        ExtensionClientIntegration extClient =
                Control.getSingleton()
                        .getExtensionLoader()
                        .getExtension(ExtensionClientIntegration.class);
        extClient.setClientRecorderHelper(null);

        ExtensionZest extZest =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionZest.class);
        extZest.setClientHelper(null);
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return DEPENDENCIES;
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("client.zest.desc");
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString("client.zest.name");
    }

    void addZestStatement(String stmt) throws Exception {
        ExtensionZest extZst =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionZest.class);
        extZst.addClientZestStatementFromString(stmt);
    }
}
