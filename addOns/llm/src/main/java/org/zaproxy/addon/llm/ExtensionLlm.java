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

import java.util.HashMap;
import java.util.Map;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.OptionsChangedListener;
import org.parosproxy.paros.extension.SessionChangedListener;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.model.Session;
import org.zaproxy.addon.llm.services.LlmCommunicationService;
import org.zaproxy.addon.llm.ui.LlmAppendAlertMenu;
import org.zaproxy.addon.llm.ui.LlmAppendHttpMessageMenu;
import org.zaproxy.addon.llm.ui.LlmChatPanel;
import org.zaproxy.addon.llm.ui.LlmOpenApiImportDialog;
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

    private ZapMenuItem llmOpenapiImportMenu;
    private LlmOpenApiImportDialog llmOpenapiImportDialog;
    private LlmReviewAlertMenu llmReviewAlertMenu;
    private LlmAppendAlertMenu llmAppendAlertMenu;
    private LlmAppendHttpMessageMenu llmAppendRequestMenu;
    private LlmAppendHttpMessageMenu llmAppendResponseMenu;
    private LlmAppendHttpMessageMenu llmAppendRequestResponseMenu;
    private LlmChatPanel llmChatPanel;
    private LlmOptions options;
    private LlmOptions prevOptions;
    private Map<String, LlmCommunicationService> commsServices = new HashMap<>();

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
        prevOptions = new LlmOptions();
        extensionHook.addOptionsParamSet(options);

        extensionHook.addOptionsChangedListener(
                new OptionsChangedListener() {

                    @Override
                    public void optionsChanged(OptionsParam optionsParam) {
                        if (options.hasCommsChanged(prevOptions)) {
                            commsServices.clear();
                            prevOptions = (LlmOptions) options.clone();
                        }
                        if (hasView()) {
                            if (options.isCommsConfigured()) {
                                getLlmOpenapiImportMenu().setEnabled(true);
                                getLlmOpenapiImportMenu()
                                        .setToolTipText(
                                                Constant.messages.getString(
                                                        "llm.topmenu.import.importOpenAPI.tooltip"));
                            } else {
                                getLlmOpenapiImportMenu().setEnabled(false);
                                getLlmOpenapiImportMenu().setToolTipText(getCommsIssue());
                            }
                        }
                    }
                });

        if (hasView()) {
            extensionHook.getHookView().addOptionPanel(new LlmOptionsPanel());
            extensionHook.getHookView().addWorkPanel(getLlmChatPanel());
            extensionHook.getHookMenu().addImportMenuItem(getLlmOpenapiImportMenu());
            extensionHook.getHookMenu().addPopupMenuItem(getLlmReviewAlertMenu());
            extensionHook.getHookMenu().addPopupMenuItem(getLlmAppendAlertMenu());
            extensionHook.getHookMenu().addPopupMenuItem(getLlmAppendRequestMenu());
            extensionHook.getHookMenu().addPopupMenuItem(getLlmAppendResponseMenu());
            extensionHook.getHookMenu().addPopupMenuItem(getLlmAppendRequestResponseMenu());

            extensionHook.addSessionListener(
                    new SessionChangedListener() {
                        @Override
                        public void sessionAboutToChange(Session session) {
                            if (llmOpenapiImportDialog != null) {
                                llmOpenapiImportDialog.clearFields();
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

        if (llmOpenapiImportDialog != null) {
            llmOpenapiImportDialog.dispose();
        }
    }

    private ZapMenuItem getLlmOpenapiImportMenu() {
        if (llmOpenapiImportMenu == null) {
            llmOpenapiImportMenu = new ZapMenuItem("llm.topmenu.import.importOpenAPI");
            llmOpenapiImportMenu.setToolTipText(
                    Constant.messages.getString("llm.topmenu.import.importOpenAPI.tooltip"));
            llmOpenapiImportMenu.addActionListener(
                    e -> {
                        if (llmOpenapiImportDialog == null) {
                            llmOpenapiImportDialog =
                                    new LlmOpenApiImportDialog(getView().getMainFrame(), this);
                        }
                        llmOpenapiImportDialog.setVisible(true);
                    });
        }
        return llmOpenapiImportMenu;
    }

    private LlmReviewAlertMenu getLlmReviewAlertMenu() {
        if (llmReviewAlertMenu == null) {
            llmReviewAlertMenu = new LlmReviewAlertMenu(this);
        }
        return llmReviewAlertMenu;
    }

    public boolean isConfigured() {
        return options != null && options.isCommsConfigured();
    }

    public String getCommsIssue() {
        return options != null ? options.getCommsIssue() : "";
    }

    /**
     * Only for testing purposes.
     *
     * @return the options
     */
    protected LlmOptions getOptions() {
        return this.options;
    }

    @Override
    public void optionsLoaded() {
        this.prevOptions = (LlmOptions) this.options.clone();
    }

    public LlmCommunicationService getCommunicationService(String commsKey) {
        if (!isConfigured()) {
            return null;
        }
        return commsServices.computeIfAbsent(commsKey, k -> new LlmCommunicationService(options));
    }

    private LlmChatPanel getLlmChatPanel() {
        if (llmChatPanel == null) {
            llmChatPanel = new LlmChatPanel(this);
        }
        return llmChatPanel;
    }

    public LlmChatPanel getLlmChatPanelPublic() {
        return getLlmChatPanel();
    }

    private LlmAppendAlertMenu getLlmAppendAlertMenu() {
        if (llmAppendAlertMenu == null) {
            llmAppendAlertMenu = new LlmAppendAlertMenu(this);
        }
        return llmAppendAlertMenu;
    }

    private LlmAppendHttpMessageMenu getLlmAppendRequestMenu() {
        if (llmAppendRequestMenu == null) {
            llmAppendRequestMenu =
                    new LlmAppendHttpMessageMenu(
                            this,
                            Constant.messages.getString("llm.menu.append.request.title"),
                            true,
                            false);
        }
        return llmAppendRequestMenu;
    }

    private LlmAppendHttpMessageMenu getLlmAppendResponseMenu() {
        if (llmAppendResponseMenu == null) {
            llmAppendResponseMenu =
                    new LlmAppendHttpMessageMenu(
                            this,
                            Constant.messages.getString("llm.menu.append.response.title"),
                            false,
                            true);
        }
        return llmAppendResponseMenu;
    }

    private LlmAppendHttpMessageMenu getLlmAppendRequestResponseMenu() {
        if (llmAppendRequestResponseMenu == null) {
            llmAppendRequestResponseMenu =
                    new LlmAppendHttpMessageMenu(
                            this,
                            Constant.messages.getString("llm.menu.append.requestresponse.title"),
                            true,
                            true);
        }
        return llmAppendRequestResponseMenu;
    }
}
