/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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

import java.awt.event.KeyEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.SessionChangedListener;
import org.parosproxy.paros.model.Session;
import org.zaproxy.addon.llm.ui.ImportDialog;
import org.zaproxy.addon.llm.ui.LlmReviewAlertMenu;
import org.zaproxy.addon.llm.ui.settings.LlmOptionsPanel;
import org.zaproxy.addon.llm.ui.settings.LlmOptionsParam;
import org.zaproxy.zap.view.ZapMenuItem;

/**
 * An extension for ZAP that enables researchers to leverage Language Learning Models (LLMs) to
 * augment the functionalities of ZAP.
 *
 * <p>{@link ExtensionAdaptor} classes are the main entry point for adding/loading functionalities
 * provided by the add-ons.
 *
 * @see #hook(ExtensionHook)
 */
public class ExtensionLlm extends ExtensionAdaptor {

    private static final Logger LOGGER = LogManager.getLogger(ExtensionLlm.class);

    public static final String NAME = "ExtensionLlm";
    protected static final String PREFIX = "llm";
    private static final String[] ROOT = {};

    private ZapMenuItem menuLLM;
    private AbstractPanel statusPanel;
    private ImportDialog importDialog;
    private LlmReviewAlertMenu llmReviewAlertMenu;
    private LlmOptionsParam llmOptionsParam;
    private LlmOptionsPanel llmOptionsPanel;

    public ExtensionLlm() {
        super(NAME);
        setI18nPrefix(PREFIX);
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        if (hasView()) {
            extensionHook.getHookMenu().addImportMenuItem(getMenuLLM());
            extensionHook.getHookMenu().addPopupMenuItem(getCheckLlmMenu());
            extensionHook.addOptionsParamSet(getOptionsParam());
            getView().getOptionsDialog().addParamPanel(ROOT, getOptionsPanel(), true);

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

    private ZapMenuItem getMenuLLM() {
        if (menuLLM == null) {
            menuLLM =
                    new ZapMenuItem(
                            "llm.topmenu.import.importOpenAPI",
                            getView().getMenuShortcutKeyStroke(KeyEvent.VK_J, 0, false));
            menuLLM.setToolTipText(
                    Constant.messages.getString("llm.topmenu.import.importOpenAPI.tooltip"));
            menuLLM.addActionListener(
                    e -> {
                        if (importDialog == null) {
                            importDialog = new ImportDialog(getView().getMainFrame(), this);
                        }
                        importDialog.setVisible(true);
                    });
        }
        return menuLLM;
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(PREFIX + ".desc");
    }

    private LlmReviewAlertMenu getCheckLlmMenu() {
        if (llmReviewAlertMenu == null) {
            llmReviewAlertMenu = new LlmReviewAlertMenu(this);
        }
        return llmReviewAlertMenu;
    }

    private LlmOptionsPanel getOptionsPanel() {
        if (llmOptionsPanel == null) {
            llmOptionsPanel = new LlmOptionsPanel();
        }
        return llmOptionsPanel;
    }

    public LlmOptionsParam getOptionsParam() {
        if (llmOptionsParam == null) {
            llmOptionsParam = new LlmOptionsParam();
        }
        return llmOptionsParam;
    }
}
