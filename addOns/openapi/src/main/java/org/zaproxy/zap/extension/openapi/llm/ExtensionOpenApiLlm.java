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
package org.zaproxy.zap.extension.openapi.llm;

import java.util.List;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.OptionsChangedListener;
import org.parosproxy.paros.extension.SessionChangedListener;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.model.Session;
import org.zaproxy.addon.llm.ExtensionLlm;
import org.zaproxy.zap.extension.openapi.ExtensionOpenApi;
import org.zaproxy.zap.view.ZapMenuItem;

public class ExtensionOpenApiLlm extends ExtensionAdaptor {

    private static final List<Class<? extends Extension>> DEPENDENCIES =
            List.of(ExtensionOpenApi.class, ExtensionLlm.class);

    private ZapMenuItem llmOpenApiImportMenu;
    private LlmOpenApiImportDialog llmOpenApiImportDialog;

    public ExtensionOpenApiLlm() {
        super("ExtensionOpenApiLlm");
    }

    @Override
    public boolean supportsDb(String type) {
        return true;
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        // Listen for LLM configuration changes
        extensionHook.addOptionsChangedListener(
                new OptionsChangedListener() {
                    @Override
                    public void optionsChanged(OptionsParam optionsParam) {
                        if (hasView()) {
                            updateMenuState();
                        }
                    }
                });

        if (hasView()) {
            extensionHook.getHookMenu().addImportMenuItem(getLlmOpenApiImportMenu());

            extensionHook.addSessionListener(
                    new SessionChangedListener() {
                        @Override
                        public void sessionAboutToChange(Session session) {
                            if (llmOpenApiImportDialog != null) {
                                llmOpenApiImportDialog.clearFields();
                            }
                        }

                        @Override
                        public void sessionChanged(Session session) {
                            updateMenuState();
                        }

                        @Override
                        public void sessionScopeChanged(Session session) {}

                        @Override
                        public void sessionModeChanged(Control.Mode mode) {}
                    });
        }
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        if (llmOpenApiImportDialog != null) {
            llmOpenApiImportDialog.dispose();
        }
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return DEPENDENCIES;
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("openapi.llm.desc");
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString("openapi.llm.name");
    }

    private ZapMenuItem getLlmOpenApiImportMenu() {
        if (llmOpenApiImportMenu == null) {
            llmOpenApiImportMenu = new ZapMenuItem("openapi.llm.topmenu.import.importOpenAPI");
            llmOpenApiImportMenu.setToolTipText(
                    Constant.messages.getString(
                            "openapi.llm.topmenu.import.importOpenAPI.tooltip"));
            llmOpenApiImportMenu.addActionListener(
                    e -> {
                        if (llmOpenApiImportDialog == null) {
                            llmOpenApiImportDialog =
                                    new LlmOpenApiImportDialog(getView().getMainFrame(), this);
                        }
                        llmOpenApiImportDialog.setVisible(true);
                    });
            updateMenuState();
        }
        return llmOpenApiImportMenu;
    }

    private void updateMenuState() {
        ExtensionLlm extLlm =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionLlm.class);
        if (extLlm.isConfigured()) {
            llmOpenApiImportMenu.setEnabled(true);
            llmOpenApiImportMenu.setToolTipText(
                    Constant.messages.getString(
                            "openapi.llm.topmenu.import.importOpenAPI.tooltip"));
        } else {
            llmOpenApiImportMenu.setEnabled(false);
            llmOpenApiImportMenu.setToolTipText(extLlm.getCommsIssue());
        }
    }
}
