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
package org.zaproxy.addon.llm;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.SessionChangedListener;
import org.parosproxy.paros.model.Session;
import org.zaproxy.addon.llm.ui.ImportDialog;
import org.zaproxy.addon.llm.ui.LlmOptionsPanel;
import org.zaproxy.addon.llm.ui.LlmReviewAlertMenu;
import org.zaproxy.zap.view.ZapMenuItem;

/**
 * An extension for ZAP that enables researchers to leverage Large Language Models (LLMs) to augment
 * the functionalities of ZAP.
 */
public class ExtensionLlm extends ExtensionAdaptor {

    public static final String NAME = "ExtensionLlm";

    protected static final String PREFIX = "llm";

    private ZapMenuItem menuLLM;
    private ImportDialog importDialog;
    private LlmReviewAlertMenu llmReviewAlertMenu;
    private LlmOptions options;

    public ExtensionLlm() {
        super(NAME);
        setI18nPrefix(PREFIX);
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString(PREFIX + ".name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(PREFIX + ".desc");
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        options = new LlmOptions();
        extensionHook.addOptionsParamSet(options);

        if (hasView()) {
            extensionHook.getHookView().addOptionPanel(new LlmOptionsPanel(this::setLlmExtEnabled));
            extensionHook.getHookMenu().addImportMenuItem(getMenuLlm());
            extensionHook.getHookMenu().addPopupMenuItem(getCheckLlmMenu());

            extensionHook.addSessionListener(
                    new SessionChangedListener() {
                        @Override
                        public void sessionAboutToChange(Session session) {
                            if (importDialog != null) {
                                importDialog.clearFields();
                            }
                        }

                        @Override
                        public void sessionChanged(Session session) {}

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
        super.unload();

        if (importDialog != null) {
            importDialog.dispose();
        }
    }

    private ZapMenuItem getMenuLlm() {
        if (menuLLM == null) {
            menuLLM = new ZapMenuItem("llm.topmenu.import.importOpenAPI");
            menuLLM.setToolTipText(
                    Constant.messages.getString("llm.topmenu.import.importOpenAPI.tooltip"));
            menuLLM.addActionListener(
                    e -> {
                        if (importDialog == null) {
                            importDialog = new ImportDialog(getView().getMainFrame(), options);
                        }
                        importDialog.setVisible(true);
                    });
        }
        return menuLLM;
    }

    private LlmReviewAlertMenu getCheckLlmMenu() {
        if (llmReviewAlertMenu == null) {
            llmReviewAlertMenu = new LlmReviewAlertMenu(options, this::isConfigured);
        }
        return llmReviewAlertMenu;
    }

    private boolean isConfigured() {
        return options.getModelProvider() != LlmProvider.NONE;
    }

    @Override
    public void optionsLoaded() {
        super.optionsLoaded();

        if (hasView()) {
            setLlmExtEnabled(isConfigured());
        }
    }

    private void setLlmExtEnabled(boolean enable) {
        getMenuLlm().setEnabled(enable);
        getCheckLlmMenu().setEnabled(enable);
    }
}
