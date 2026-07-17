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

import dev.langchain4j.model.chat.listener.ChatModelListener;
import dev.langchain4j.service.tool.ToolProvider;
import java.net.URL;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import javax.swing.ImageIcon;
import javax.swing.SwingUtilities;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.OptionsChangedListener;
import org.parosproxy.paros.model.OptionsParam;
import org.zaproxy.addon.llm.services.LlmCommunicationService;
import org.zaproxy.addon.llm.services.LlmGuiResponseHandler;
import org.zaproxy.addon.llm.services.LlmLogResponseHandler;
import org.zaproxy.addon.llm.ui.LlmAppendAlertMenu;
import org.zaproxy.addon.llm.ui.LlmAppendHttpMessageMenu;
import org.zaproxy.addon.llm.ui.LlmChatPanel;
import org.zaproxy.addon.llm.ui.LlmChatTabPanel;
import org.zaproxy.addon.llm.ui.LlmOptionsPanel;
import org.zaproxy.addon.llm.ui.LlmSelectorButton;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.utils.ThreadUtils;

/**
 * An extension for ZAP that enables researchers to leverage Large Language Models (LLMs) to augment
 * the functionalities of ZAP.
 */
public class ExtensionLlm extends ExtensionAdaptor {

    public static final String NAME = "ExtensionLlm";

    protected static final String PREFIX = "llm";

    private LlmChatPanel llmChatPanel;
    private LlmOptions options;
    private LlmOptions prevOptions;
    private Map<String, LlmCommunicationService> commsServices = new ConcurrentHashMap<>();
    private final List<ToolProvider> toolProviders = new CopyOnWriteArrayList<>();
    private final AtomicInteger toolProvidersVersion = new AtomicInteger();

    private static final Logger LOGGER = LogManager.getLogger(ExtensionLlm.class);

    public static ImageIcon createIcon(String resourcePath) {
        URL url = ExtensionLlm.class.getResource(resourcePath);
        if (url == null) {
            LOGGER.error("Missing resource: {}", resourcePath);
            return null;
        }
        return DisplayUtils.getScaledIcon(url);
    }

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
                            if (llmChatPanel != null) {
                                SwingUtilities.invokeLater(llmChatPanel::refreshProviders);
                            }
                        }
                    }
                });

        if (hasView()) {
            llmChatPanel = new LlmChatPanel(this);
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

    private LlmChatTabPanel getChatTab(String commsKey, String panelName) {
        if (this.llmChatPanel == null) {
            return null;
        }
        AtomicReference<LlmChatTabPanel> result = new AtomicReference<>();
        try {
            ThreadUtils.invokeAndWait(
                    () ->
                            result.set(
                                    this.llmChatPanel
                                            .getTabbedPane()
                                            .getTaggedTab(commsKey, panelName)));
        } catch (Exception e) {
            LOGGER.error("Failed to get chat tab for comms key: {}", commsKey, e);
        }
        return result.get();
    }

    /**
     * Returns the named chat tab, creating it if it does not yet exist. Returns {@code null} when
     * there is no view (headless/daemon mode).
     */
    public LlmChatTabPanel getOrCreateChatTab(String commsKey, String tabName) {
        return getChatTab(commsKey, tabName);
    }

    @Override
    public void optionsLoaded() {
        this.prevOptions = this.options.clone();
        if (llmChatPanel != null) {
            SwingUtilities.invokeLater(llmChatPanel::refreshProviders);
        }
    }

    private void optionsReset() {
        commsServices.clear();
        prevOptions = options.clone();
    }

    public void addToolProvider(ToolProvider provider) {
        toolProviders.add(provider);
        toolProvidersVersion.incrementAndGet();
        commsServices.clear();
    }

    public void removeToolProvider(ToolProvider provider) {
        toolProviders.remove(provider);
        toolProvidersVersion.incrementAndGet();
        commsServices.clear();
    }

    public int getToolProvidersVersion() {
        return toolProvidersVersion.get();
    }

    public LlmCommunicationService getCommunicationService(String commsKey, String outputTabName) {
        if (!isConfigured()) {
            return null;
        }
        return commsServices.computeIfAbsent(
                commsKey,
                k -> {
                    ChatModelListener listener = null;
                    if (hasView() && outputTabName != null) {
                        listener = new LlmGuiResponseHandler(getChatTab(commsKey, outputTabName));
                    } else {
                        listener = new LlmLogResponseHandler(commsKey);
                    }
                    return new LlmCommunicationService(
                            options.getDefaultProviderConfig(),
                            options.getDefaultModelName(),
                            listener,
                            List.copyOf(toolProviders));
                });
    }

    /**
     * Caches a tab's communication service under the tab tag so it can be discarded when the tab is
     * closed.
     */
    public void cacheTabCommunicationService(String tag, LlmCommunicationService service) {
        if (tag != null && service != null) {
            commsServices.put(tag, service);
        }
    }

    /**
     * Removes the cached communication service for the given key, discarding its conversation
     * history.
     */
    public void removeCommunicationService(String commsKey) {
        if (commsKey != null) {
            commsServices.remove(commsKey);
        }
    }

    public List<LlmProviderConfig> getProviderConfigs() {
        return options != null ? options.getProviderConfigs() : List.of();
    }

    public LlmProviderConfig getDefaultProviderConfig() {
        return options != null ? options.getDefaultProviderConfig() : null;
    }

    public String getDefaultModelName() {
        return options != null ? options.getDefaultModelName() : "";
    }

    /**
     * Builds a {@link LlmCommunicationService} using the given provider config, bypassing the
     * global default. Used by individual chat tabs that maintain their own provider selection.
     */
    public LlmCommunicationService buildCommunicationService(
            LlmProviderConfig providerConfig, String modelName, ChatModelListener listener) {
        if (providerConfig == null || LlmProvider.NONE.equals(providerConfig.getProvider())) {
            return null;
        }
        if (providerConfig.getProvider().isEndpointRequired()
                && (providerConfig.getEndpoint() == null
                        || providerConfig.getEndpoint().isBlank())) {
            return null;
        }
        if (providerConfig.getProvider().isModelRequired()
                && providerConfig.getModels().isEmpty()) {
            return null;
        }
        return new LlmCommunicationService(
                providerConfig, modelName, listener, List.copyOf(toolProviders));
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
