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

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import org.apache.commons.configuration.HierarchicalConfiguration;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.common.VersionedAbstractParam;

public class LlmOptions extends VersionedAbstractParam {

    /**
     * The version of the configurations. Used to keep track of configurations changes between
     * releases, if updates are needed.
     *
     * <p>It only needs to be updated for configurations changes (not releases of the add-on).
     */
    private static final int CURRENT_VERSION = 1;

    private static final String BASE_KEY = "llm";

    public static final String MODEL_PROVIDER_PROPERTY = BASE_KEY + ".modelprovider";
    public static final String APIKEY_PROPERTY = BASE_KEY + ".apikey";
    public static final String ENDPOINT_PROPERTY = BASE_KEY + ".endpoint";
    public static final String MODEL_NAME_PROPERTY = BASE_KEY + ".modelname";

    private static final String PROVIDERS_BASE_KEY = BASE_KEY + ".providers";
    private static final String ALL_PROVIDERS_KEY = PROVIDERS_BASE_KEY + ".provider";
    private static final String DEFAULT_PROVIDER_MODEL = PROVIDERS_BASE_KEY + ".defaultModel";
    private static final String DEFAULT_PROVIDER_PROPERTY = PROVIDERS_BASE_KEY + ".default";
    private static final String PROVIDER_NAME_KEY = "name";
    private static final String PROVIDER_TYPE_KEY = "type";
    private static final String PROVIDER_APIKEY_KEY = "apikey";
    private static final String PROVIDER_ENDPOINT_KEY = "endpoint";
    private static final String PROVIDER_MODELS_KEY = "models.model";

    private List<LlmProviderConfig> providerConfigs = new ArrayList<>();
    private String defaultProviderName;
    private String defaultModelName;

    private static final Logger LOGGER = LogManager.getLogger(LlmOptions.class);

    @Override
    protected String getConfigVersionKey() {
        return BASE_KEY + VERSION_ATTRIBUTE;
    }

    @Override
    protected int getCurrentVersion() {
        return CURRENT_VERSION;
    }

    @Override
    protected void parseImpl() {
        List<HierarchicalConfiguration> fields =
                ((HierarchicalConfiguration) getConfig()).configurationsAt(ALL_PROVIDERS_KEY);
        List<LlmProviderConfig> configs = new ArrayList<>(fields.size());
        Set<String> names = new HashSet<>();
        for (HierarchicalConfiguration sub : fields) {
            String name = StringUtils.trimToEmpty(sub.getString(PROVIDER_NAME_KEY, ""));
            if (name.isEmpty() || !names.add(name)) {
                continue;
            }

            LlmProvider provider = LlmProvider.NONE;
            try {
                provider =
                        LlmProvider.valueOf(
                                sub.getString(PROVIDER_TYPE_KEY, LlmProvider.NONE.name()));
            } catch (IllegalArgumentException e) {
                LOGGER.error("LLM Provider not recognised: {}", sub.getString(PROVIDER_TYPE_KEY));
                continue;
            }
            String apiKey = sub.getString(PROVIDER_APIKEY_KEY, "");
            String endpoint = sub.getString(PROVIDER_ENDPOINT_KEY, "");

            // Extract the models
            List<String> models = new ArrayList<>();
            for (Object model : sub.getList(PROVIDER_MODELS_KEY)) {
                if (model != null && StringUtils.isNotBlank(model.toString())) {
                    models.add(model.toString().trim());
                }
            }
            configs.add(new LlmProviderConfig(name, provider, apiKey, endpoint, models));
        }
        this.providerConfigs = configs;
        defaultProviderName = getString(DEFAULT_PROVIDER_PROPERTY, "");
        defaultModelName = getString(DEFAULT_PROVIDER_MODEL, "");
    }

    @Override
    protected void updateConfigsImpl(int fileVersion) {}

    public LlmProvider getDefaultModelProvider() {
        LlmProviderConfig config = getDefaultProviderConfig();
        return config != null ? config.getProvider() : LlmProvider.NONE;
    }

    public boolean hasCommsChanged(LlmOptions options) {
        return !Objects.equals(this.providerConfigs, options.providerConfigs)
                || !Objects.equals(this.defaultProviderName, options.defaultProviderName)
                || !Objects.equals(this.defaultModelName, options.defaultModelName);
    }

    public boolean isCommsConfigured() {
        LlmProviderConfig config = getDefaultProviderConfig();
        if (config == null || LlmProvider.NONE.equals(config.getProvider())) {
            return false;
        }
        return !config.getProvider().supportsEndpoint()
                || !StringUtils.isBlank(config.getEndpoint());
    }

    public String getCommsIssue() {
        if (StringUtils.isBlank(defaultProviderName)) {
            return Constant.messages.getString("llm.error.provider");
        }
        LlmProviderConfig config = getDefaultProviderConfigInternal();
        if (config == null || LlmProvider.NONE.equals(config.getProvider())) {
            return Constant.messages.getString("llm.error.provider");
        }
        if (config.getProvider().supportsEndpoint() && StringUtils.isBlank(config.getEndpoint())) {
            return Constant.messages.getString("llm.error.endpoint");
        }
        return null;
    }

    public List<LlmProviderConfig> getProviderConfigs() {
        List<LlmProviderConfig> configs = new ArrayList<>(providerConfigs.size());
        for (LlmProviderConfig config : providerConfigs) {
            configs.add(new LlmProviderConfig(config));
        }
        return configs;
    }

    public void setProviderConfigs(List<LlmProviderConfig> providerConfigs) {
        Objects.requireNonNull(providerConfigs);
        this.providerConfigs = new ArrayList<>(providerConfigs.size());
        for (LlmProviderConfig config : providerConfigs) {
            this.providerConfigs.add(new LlmProviderConfig(config));
        }
        persistProviderConfigs();
    }

    public LlmProviderConfig getProviderConfig(String name) {
        if (StringUtils.isBlank(name)) {
            return null;
        }
        for (LlmProviderConfig config : providerConfigs) {
            if (name.equals(config.getName())) {
                return new LlmProviderConfig(config);
            }
        }
        return null;
    }

    public LlmProviderConfig getDefaultProviderConfig() {
        LlmProviderConfig config = getDefaultProviderConfigInternal();
        return config != null ? new LlmProviderConfig(config) : null;
    }

    private void persistProviderConfigs() {
        ((HierarchicalConfiguration) getConfig()).clearTree(ALL_PROVIDERS_KEY);

        for (int i = 0, size = providerConfigs.size(); i < size; ++i) {
            String elementBaseKey = ALL_PROVIDERS_KEY + "(" + i + ").";
            LlmProviderConfig config = providerConfigs.get(i);
            getConfig().setProperty(elementBaseKey + PROVIDER_NAME_KEY, config.getName());
            getConfig()
                    .setProperty(elementBaseKey + PROVIDER_TYPE_KEY, config.getProvider().name());
            getConfig().setProperty(elementBaseKey + PROVIDER_APIKEY_KEY, config.getApiKey());
            getConfig().setProperty(elementBaseKey + PROVIDER_ENDPOINT_KEY, config.getEndpoint());
            ((HierarchicalConfiguration) getConfig()).clearTree(elementBaseKey + "models");
            List<String> models = config.getModels();
            for (int j = 0; j < models.size(); ++j) {
                getConfig()
                        .setProperty(
                                elementBaseKey + PROVIDER_MODELS_KEY + "(" + j + ")",
                                models.get(j));
            }
        }

        getConfig().setProperty(DEFAULT_PROVIDER_PROPERTY, defaultProviderName);
        getConfig().setProperty(DEFAULT_PROVIDER_MODEL, defaultModelName);
    }

    public String getDefaultProviderName() {
        return defaultProviderName;
    }

    public void setDefaultProviderName(String defaultProviderName) {
        this.defaultProviderName = StringUtils.trimToEmpty(defaultProviderName);
        getConfig().setProperty(DEFAULT_PROVIDER_PROPERTY, this.defaultProviderName);
    }

    public String getDefaultModelName() {
        return defaultModelName;
    }

    public void setDefaultModelName(String defaultModelName) {
        this.defaultModelName = StringUtils.trimToEmpty(defaultModelName);
        getConfig().setProperty(DEFAULT_PROVIDER_MODEL, this.defaultModelName);
    }

    private LlmProviderConfig getDefaultProviderConfigInternal() {
        if (StringUtils.isBlank(defaultProviderName) || providerConfigs.isEmpty()) {
            return null;
        }
        for (LlmProviderConfig config : providerConfigs) {
            if (defaultProviderName.equals(config.getName())) {
                return config;
            }
        }
        return providerConfigs.get(0);
    }

    @Override
    public LlmOptions clone() {
        LlmOptions clone = (LlmOptions) super.clone();
        clone.providerConfigs = getProviderConfigs();
        clone.defaultProviderName = defaultProviderName;
        clone.defaultModelName = defaultModelName;
        return clone;
    }
}
