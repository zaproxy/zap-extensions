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
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import javax.swing.ImageIcon;
import javax.swing.SwingUtilities;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.lang3.StringUtils;
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
import org.zaproxy.addon.llm.services.LlmToolExecutionHandler;
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
    private final Map<LlmProvider, LlmChatModelFactory> chatModelFactories =
            new ConcurrentHashMap<>();
    private final Map<LlmProvider, LlmLocalModelDownloadUi> localModelDownloadUis =
            new ConcurrentHashMap<>();

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

    /**
     * Registers a factory that can create chat models for a provider implemented in another add-on.
     *
     * @param factory the factory to register
     */
    public void registerChatModelFactory(LlmChatModelFactory factory) {
        if (factory == null || factory.getProvider() == null) {
            return;
        }
        chatModelFactories.put(factory.getProvider(), factory);
        commsServices.clear();
    }

    /**
     * Unregisters a previously registered chat model factory.
     *
     * @param factory the factory to unregister
     */
    public void unregisterChatModelFactory(LlmChatModelFactory factory) {
        if (factory == null || factory.getProvider() == null) {
            return;
        }
        chatModelFactories.remove(factory.getProvider(), factory);
        commsServices.clear();
    }

    /**
     * Returns the registered factory for the given provider, or {@code null} if none is registered.
     *
     * @param provider the provider
     * @return the factory, or {@code null}
     */
    public LlmChatModelFactory getChatModelFactory(LlmProvider provider) {
        return provider == null ? null : chatModelFactories.get(provider);
    }

    /**
     * Returns {@code true} if a chat model factory is registered for the given provider.
     *
     * @param provider the provider
     * @return {@code true} if a factory is available
     */
    public boolean hasChatModelFactory(LlmProvider provider) {
        return getChatModelFactory(provider) != null;
    }

    /**
     * Registers UI that can download a local model for a provider implemented in another add-on.
     *
     * @param downloadUi the download UI to register
     */
    public void registerLocalModelDownloadUi(LlmLocalModelDownloadUi downloadUi) {
        if (downloadUi == null || downloadUi.getProvider() == null) {
            return;
        }
        localModelDownloadUis.put(downloadUi.getProvider(), downloadUi);
    }

    /**
     * Unregisters a previously registered local model download UI.
     *
     * @param downloadUi the download UI to unregister
     */
    public void unregisterLocalModelDownloadUi(LlmLocalModelDownloadUi downloadUi) {
        if (downloadUi == null || downloadUi.getProvider() == null) {
            return;
        }
        localModelDownloadUis.remove(downloadUi.getProvider(), downloadUi);
    }

    /**
     * Returns the registered local model download UI for the given provider, or {@code null}.
     *
     * @param provider the provider
     * @return the download UI, or {@code null}
     */
    public LlmLocalModelDownloadUi getLocalModelDownloadUi(LlmProvider provider) {
        return provider == null ? null : localModelDownloadUis.get(provider);
    }

    /**
     * Returns {@code true} if a local model download UI is registered for the given provider.
     *
     * @param provider the provider
     * @return {@code true} if download UI is available
     */
    public boolean hasLocalModelDownloadUi(LlmProvider provider) {
        return getLocalModelDownloadUi(provider) != null;
    }

    public LlmCommunicationService getCommunicationService(String commsKey, String outputTabName) {
        if (!isConfigured()) {
            return null;
        }
        return commsServices.computeIfAbsent(
                commsKey,
                k -> {
                    ChatModelListener listener = null;
                    LlmToolExecutionHandler toolHandler = null;
                    if (hasView() && outputTabName != null) {
                        LlmChatTabPanel chatTab = getChatTab(commsKey, outputTabName);
                        listener = new LlmGuiResponseHandler(chatTab);
                        toolHandler = new LlmToolExecutionHandler(chatTab);
                    } else {
                        listener = new LlmLogResponseHandler(commsKey);
                    }
                    return new LlmCommunicationService(
                            options.getDefaultProviderConfig(),
                            options.getDefaultModelName(),
                            listener,
                            toolsFor(options.getDefaultProviderConfig()),
                            toolHandler);
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
     *
     * @param includeTools if {@code true}, registered tool providers are added to the LLM context
     *     when the provider is trusted; otherwise the service is built without tools
     * @param toolExecutionHandler optional handler that displays tool calls/results in the chat UI
     */
    public LlmCommunicationService buildCommunicationService(
            LlmProviderConfig providerConfig,
            String modelName,
            ChatModelListener listener,
            boolean includeTools,
            LlmToolExecutionHandler toolExecutionHandler) {
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
                providerConfig,
                modelName,
                listener,
                includeTools ? toolsFor(providerConfig) : List.of(),
                toolExecutionHandler);
    }

    private List<ToolProvider> toolsFor(LlmProviderConfig providerConfig) {
        if (providerConfig == null || !providerConfig.isTrusted()) {
            return List.of();
        }
        return List.copyOf(toolProviders);
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
        refreshChatProviders();

        try {
            options.getConfig().save();
        } catch (ConfigurationException e) {
            LOGGER.error("Failed to save LLM default provider selection:", e);
        }
    }

    /**
     * Adds or replaces a provider configuration by name and optionally selects it as the default
     * (using the first model in the config).
     *
     * <p>Cached communication services are kept unless this change makes them unusable (for example
     * the selected model was removed, or the provider connection details changed). Chat tab
     * services are preserved across default-selection changes; non-tab caches (e.g. OpenAPI) are
     * dropped when the global default changes so callers pick up the new default.
     *
     * @param config the provider configuration
     * @param setAsDefault {@code true} to make this the default provider/model
     */
    public void configureProvider(LlmProviderConfig config, boolean setAsDefault) {
        if (options == null || config == null || StringUtils.isBlank(config.getName())) {
            return;
        }

        LlmProviderConfig previous = options.getProviderConfig(config.getName());
        String previousDefaultName = options.getDefaultProviderName();
        String previousDefaultModel = options.getDefaultModelName();

        List<LlmProviderConfig> configs = getProviderConfigs();
        configs.removeIf(existing -> config.getName().equals(existing.getName()));
        configs.add(new LlmProviderConfig(config));
        options.setProviderConfigs(configs);

        if (setAsDefault) {
            String modelName = config.getModels().isEmpty() ? "" : config.getModels().get(0);
            options.setDefaultProviderName(config.getName());
            options.setDefaultModelName(modelName);
        } else if (config.getName().equals(options.getDefaultProviderName())
                && StringUtils.isNotEmpty(options.getDefaultModelName())
                && !config.getModels().contains(options.getDefaultModelName())) {
            // The configured default model was removed from this provider.
            options.setDefaultModelName(
                    config.getModels().isEmpty() ? "" : config.getModels().get(0));
        }

        invalidateCommsAfterProviderChange(
                previous, config, previousDefaultName, previousDefaultModel);
        prevOptions = options.clone();

        try {
            options.getConfig().save();
        } catch (ConfigurationException e) {
            LOGGER.error("Failed to save LLM provider configuration:", e);
        }
        refreshChatProviders();
    }

    /**
     * Drops cached services that can no longer run with the updated provider config. Unrelated
     * conversations are left alone.
     */
    private void invalidateCommsAfterProviderChange(
            LlmProviderConfig previous,
            LlmProviderConfig updated,
            String previousDefaultName,
            String previousDefaultModel) {
        boolean defaultChanged =
                !Objects.equals(previousDefaultName, options.getDefaultProviderName())
                        || !Objects.equals(previousDefaultModel, options.getDefaultModelName());
        boolean connectionChanged = previous != null && !sameCommsIdentity(previous, updated);

        Set<String> removedModels = new HashSet<>();
        if (previous != null) {
            removedModels.addAll(previous.getModels());
            removedModels.removeAll(updated.getModels());
        }

        if (!connectionChanged && removedModels.isEmpty() && !defaultChanged) {
            return;
        }

        Set<String> chatTabTags = getChatTabTags();
        commsServices
                .entrySet()
                .removeIf(
                        entry -> {
                            LlmCommunicationService service = entry.getValue();
                            if (service == null || service.getPconf() == null) {
                                return false;
                            }
                            String serviceProvider = service.getPconf().getName();
                            String serviceModel = service.getModelName();

                            if (updated.getName().equals(serviceProvider)) {
                                if (connectionChanged) {
                                    return true;
                                }
                                if (removedModels.contains(serviceModel)) {
                                    return true;
                                }
                            }

                            // Global default changed: drop non-tab caches built on the old default
                            // so callers (OpenAPI, etc.) rebuild; keep chat tab conversations.
                            return defaultChanged
                                    && !chatTabTags.contains(entry.getKey())
                                    && Objects.equals(previousDefaultName, serviceProvider)
                                    && Objects.equals(previousDefaultModel, serviceModel);
                        });
    }

    private Set<String> getChatTabTags() {
        if (llmChatPanel == null || llmChatPanel.getTabbedPane() == null) {
            return Set.of();
        }
        return llmChatPanel.getTabbedPane().getChatTabTags();
    }

    /**
     * Whether two configs share the same connection identity (ignoring the models list). Matches
     * {@link LlmChatTabPanel#sameTabComms} connection fields so adding/removing unused models does
     * not wipe conversation history.
     */
    static boolean sameCommsIdentity(LlmProviderConfig a, LlmProviderConfig b) {
        return a != null
                && b != null
                && Objects.equals(a.getName(), b.getName())
                && Objects.equals(a.getProvider(), b.getProvider())
                && Objects.equals(a.getApiKey(), b.getApiKey())
                && Objects.equals(a.getEndpoint(), b.getEndpoint());
    }

    private void refreshChatProviders() {
        if (llmChatPanel != null) {
            SwingUtilities.invokeLater(llmChatPanel::refreshProviders);
        }
    }
}
