/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
package org.zaproxy.zap.extension.alertFilters.llm;

import java.util.List;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.addon.llm.ExtensionLlm;
import org.zaproxy.zap.extension.alert.ExtensionAlert;
import org.zaproxy.zap.extension.alertFilters.ExtensionAlertFilters;

public class ExtensionAlertFiltersLlm extends ExtensionAdaptor {

    private static final List<Class<? extends Extension>> DEPENDENCIES =
            List.of(ExtensionAlertFilters.class, ExtensionLlm.class);

    public ExtensionAlertFiltersLlm() {
        super("ExtensionAlertFiltersLlm");
    }

    @Override
    public boolean supportsDb(String type) {
        return true;
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);
        if (hasView()) {
            extensionHook
                    .getHookMenu()
                    .addPopupMenuItem(
                            new LlmReviewAlertMenu(
                                    Control.getSingleton()
                                            .getExtensionLoader()
                                            .getExtension(ExtensionLlm.class),
                                    Control.getSingleton()
                                            .getExtensionLoader()
                                            .getExtension(ExtensionAlert.class)));
        }
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return DEPENDENCIES;
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("alertFilters.llm.desc");
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString("alertFilters.llm.name");
    }
}
