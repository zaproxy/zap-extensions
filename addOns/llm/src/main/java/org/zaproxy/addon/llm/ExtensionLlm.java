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

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.OptionsChangedListener;
import org.parosproxy.paros.model.OptionsParam;
import org.zaproxy.addon.llm.services.LlmCommunicationService;
import org.zaproxy.addon.llm.ui.LlmAppendAlertMenu;
import org.zaproxy.addon.llm.ui.LlmAppendHttpMessageMenu;
import org.zaproxy.addon.llm.ui.LlmChatPanel;
import org.zaproxy.addon.llm.ui.LlmOptionsPanel;
import org.zaproxy.addon.llm.ui.LlmSelectorButton;

/**
 * An extension for ZAP that enables researchers to leverage Large Language Models (LLMs) to augment
 * the functionalities of ZAP.
 */
public class ExtensionLlm extends ExtensionAdaptor {

    public static final String NAME = "ExtensionLlm";

    protected static final String PREFIX = "llm";

    private LlmOptions options;
    private LlmOptions prevOptions;
    private Map<String, LlmCommunicationService> commsServices =
            Collections.synchronizedMap(new HashMap<>());

    private static final Logger LOGGER = LogManager.getLogger(ExtensionLlm.class);

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
                            optionsReset();
                        }
                    }
                });

        if (hasView()) {
            LlmChatPanel llmChatPanel = new LlmChatPanel(this);
            extensionHook.getHookView().addOptionPanel(new LlmOptionsPanel());
            extensionHook
                    .getHookView()
                    .addMainToolBarComponent(new LlmSelectorButton(this, options));
            extensionHook.getHookView().addWorkPanel(llmChatPanel);
            extensionHook.getHookMenu().addPopupMenuItem(new LlmAppendAlertMenu(llmChatPanel));
            extensionHook
                    .getHookMenu()
                    .addPopupMenuItem(
                            new LlmAppendHttpMessageMenu(
                                    llmChatPanel,
                                    Constant.messages.getString("llm.menu.append.request.title"),
                                    true,
                                    false));
            extensionHook
                    .getHookMenu()
                    .addPopupMenuItem(
                            new LlmAppendHttpMessageMenu(
                                    llmChatPanel,
                                    Constant.messages.getString("llm.menu.append.response.title"),
                                    false,
                                    true));
            extensionHook
                    .getHookMenu()
                    .addPopupMenuItem(
                            new LlmAppendHttpMessageMenu(
                                    llmChatPanel,
                                    Constant.messages.getString(
                                            "llm.menu.append.requestresponse.title"),
                                    true,
                                    true));
        }
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        super.unload();
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
        this.prevOptions = this.options.clone();
    }

    private void optionsReset() {
        commsServices.clear();
        prevOptions = options.clone();
    }

    public LlmCommunicationService getCommunicationService(String commsKey, String outputTabName) {
        if (!isConfigured()) {
            return null;
        }
        return commsServices.computeIfAbsent(
                commsKey,
                k ->
                        new LlmCommunicationService(
                                options.getDefaultProviderConfig(),
                                options.getDefaultModelName(),
                                outputTabName));
    }

    public void setDefaultProvider(String name, String modelName) {
        if (name == null) {
            return;
        }

        String providerName = name;
        if (LlmProvider.NONE.toString().equals(providerName)) {
            providerName = "";
            modelName = "";
        }

        if (providerName.equals(options.getDefaultProviderName())
                && modelName.equals(options.getDefaultModelName())) {
            return;
        }

        options.setDefaultProviderName(providerName);
        options.setDefaultModelName(modelName);
        this.optionsReset();

        try {
            options.getConfig().save();
        } catch (ConfigurationException e) {
            LOGGER.error("Failed to save LLM default provider selection:", e);
        }
    }
}
