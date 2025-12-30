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
package org.zaproxy.zap.extension.llmheader;

import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.extension.alert.ExtensionAlert;

public class ExtensionLLMHeaderAnalyzer extends ExtensionAdaptor {

    public static final String NAME = "ExtensionLLMHeaderAnalyzer";

    private LLMHeaderOptions options;
    private LLMHeaderOptionsPanel optionsPanel;
    private LLMHeaderListener listener;
    private LLMContextMenuItem contextMenuItem;

    public ExtensionLLMHeaderAnalyzer() {
        super(NAME);
        setI18nPrefix("llmheader");
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        extensionHook.addOptionsParamSet(getOptions());

        if (getView() != null) {
            extensionHook.getHookView().addOptionPanel(getOptionsPanel());
            extensionHook.getHookMenu().addPopupMenuItem(getContextMenuItem());
        }

        ExtensionAlert extAlert =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionAlert.class);
        listener = new LLMHeaderListener(getOptions(), extAlert);
        HttpSender.addListener(listener);
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        super.unload();
        if (listener != null) {
            HttpSender.removeListener(listener);
        }
        LLMRequestManager.getInstance().shutdown();
    }

    private LLMHeaderOptions getOptions() {
        if (options == null) {
            options = new LLMHeaderOptions();
        }
        return options;
    }

    private LLMHeaderOptionsPanel getOptionsPanel() {
        if (optionsPanel == null) {
            optionsPanel = new LLMHeaderOptionsPanel();
        }
        return optionsPanel;
    }

    private LLMContextMenuItem getContextMenuItem() {
        if (contextMenuItem == null) {
            contextMenuItem = new LLMContextMenuItem(getOptions());
        }
        return contextMenuItem;
    }
}
