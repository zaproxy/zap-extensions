/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.addon.llm.automation;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.apache.commons.lang3.StringUtils;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.llm.LlmOptions;
import org.zaproxy.addon.llm.LlmProvider;
import org.zaproxy.addon.llm.LlmProviderConfig;
import org.zaproxy.addon.llm.automation.LlmConfigJob.Parameters;
import org.zaproxy.addon.llm.automation.LlmConfigJob.Provider;

/**
 * Works out the providers and defaults that result from applying the providers of an {@link
 * LlmConfigJob} to the existing options, along with any problems found.
 */
final class LlmProviderConfigMerger {

    /** The outcome of a merge, the providers and defaults are only valid if there are no errors. */
    record Result(
            List<LlmProviderConfig> providers,
            String defaultProvider,
            String defaultModel,
            List<String> errors) {}

    private static final String VALID_TYPES =
            Stream.of(LlmProvider.values())
                    .filter(t -> t != LlmProvider.NONE)
                    .map(LlmProvider::name)
                    .collect(Collectors.joining(", "));

    private LlmProviderConfigMerger() {}

    static Result merge(LlmOptions options, Parameters parameters, List<Provider> specified) {
        List<String> errors = new ArrayList<>();
        Map<String, LlmProviderConfig> merged = new LinkedHashMap<>();
        if (!Boolean.TRUE.equals(parameters.getDeleteExisting())) {
            options.getProviderConfigs().forEach(c -> merged.put(c.getName(), c));
        }

        Set<String> seen = new HashSet<>();
        for (Provider provider : specified) {
            String name = StringUtils.trimToEmpty(provider.getName());
            if (name.isEmpty()) {
                errors.add(Constant.messages.getString("llm.configjob.error.name"));
            } else if (!seen.add(name)) {
                errors.add(Constant.messages.getString("llm.configjob.error.duplicate", name));
            } else {
                LlmProviderConfig config = toConfig(name, provider, errors);
                if (config != null) {
                    merged.put(name, config);
                }
            }
        }

        return new Result(
                List.copyOf(merged.values()),
                resolveDefaultProvider(options, parameters, merged, errors),
                resolveDefaultModel(options, parameters, merged, errors),
                errors);
    }

    /**
     * Validates the plan on its own, without considering the current configuration, as the job
     * might be run against a different one. Every provider must be complete, so it can't rely on an
     * existing provider supplying missing details, and any defaults must refer to providers and
     * models defined in the plan.
     */
    static List<String> validatePlan(Parameters parameters, List<Provider> specified) {
        List<String> errors = new ArrayList<>();
        Map<String, Provider> byName = new LinkedHashMap<>();
        for (Provider provider : specified) {
            String name = StringUtils.trimToEmpty(provider.getName());
            if (name.isEmpty()) {
                errors.add(Constant.messages.getString("llm.configjob.error.name"));
                continue;
            }
            if (byName.putIfAbsent(name, provider) != null) {
                errors.add(Constant.messages.getString("llm.configjob.error.duplicate", name));
                continue;
            }
            toConfig(name, provider, errors);
        }

        String defaultProvider = StringUtils.trimToNull(parameters.getDefaultProvider());
        if (defaultProvider != null && !byName.containsKey(defaultProvider)) {
            errors.add(
                    Constant.messages.getString(
                            "llm.configjob.error.defaultprovider", defaultProvider));
        }
        String defaultModel = StringUtils.trimToNull(parameters.getDefaultModel());
        if (defaultModel != null && !byName.isEmpty()) {
            String providerName =
                    defaultProvider != null ? defaultProvider : byName.keySet().iterator().next();
            Provider provider = byName.get(providerName);
            if (provider != null && !cleanModels(provider).contains(defaultModel)) {
                errors.add(
                        Constant.messages.getString(
                                "llm.configjob.error.defaultmodel", defaultModel, providerName));
            }
        }
        return errors;
    }

    /**
     * Parses the name of a provider type, ignoring case.
     *
     * @return the type, or {@code null} if it's blank, unknown or {@link LlmProvider#NONE}, which
     *     isn't a real provider
     */
    static LlmProvider parseType(String name) {
        return Stream.of(LlmProvider.values())
                .filter(
                        t ->
                                t != LlmProvider.NONE
                                        && t.name().equalsIgnoreCase(StringUtils.trimToEmpty(name)))
                .findFirst()
                .orElse(null);
    }

    /** Gets the type of the provider, reporting an error if it's missing or not valid. */
    private static LlmProvider resolveType(String name, Provider provider, List<String> errors) {
        if (StringUtils.isBlank(provider.getType())) {
            errors.add(Constant.messages.getString("llm.configjob.error.type", name, VALID_TYPES));
            return null;
        }
        LlmProvider type = parseType(provider.getType());
        if (type == null) {
            errors.add(
                    Constant.messages.getString(
                            "llm.configjob.error.badtype", name, provider.getType(), VALID_TYPES));
        }
        return type;
    }

    private static List<String> cleanModels(Provider provider) {
        if (provider.getModels() == null) {
            return List.of();
        }
        return provider.getModels().stream()
                .map(StringUtils::trimToNull)
                .filter(Objects::nonNull)
                .toList();
    }

    /**
     * Creates the configuration of a provider, which has to be complete as it replaces any existing
     * provider with the same name.
     *
     * @return the configuration, or {@code null} if the provider has no valid type, any other
     *     problems are only reported in the errors
     */
    private static LlmProviderConfig toConfig(String name, Provider provider, List<String> errors) {
        LlmProvider type = resolveType(name, provider, errors);
        if (type == null) {
            return null;
        }

        LlmProviderConfig config =
                new LlmProviderConfig(
                        name,
                        type,
                        StringUtils.defaultString(provider.getApiKey()),
                        StringUtils.defaultString(provider.getEndpoint()),
                        cleanModels(provider),
                        provider.getTrusted() != null
                                ? provider.getTrusted()
                                : type.isTrustedByDefault(),
                        provider.getTimeout() != null
                                ? provider.getTimeout()
                                : LlmProviderConfig.DEFAULT_TIMEOUT_SECONDS);
        if (type.isEndpointRequired() && StringUtils.isBlank(config.getEndpoint())) {
            errors.add(Constant.messages.getString("llm.configjob.error.endpoint", name));
        }
        if (type.isModelRequired() && config.getModels().isEmpty()) {
            errors.add(Constant.messages.getString("llm.configjob.error.models", name));
        }
        return config;
    }

    /**
     * Uses the requested default provider, else the existing one, else the first provider. An empty
     * name means there are no providers.
     */
    private static String resolveDefaultProvider(
            LlmOptions options,
            Parameters parameters,
            Map<String, LlmProviderConfig> merged,
            List<String> errors) {
        String requested = StringUtils.trimToNull(parameters.getDefaultProvider());
        if (requested != null && !merged.containsKey(requested)) {
            errors.add(
                    Constant.messages.getString("llm.configjob.error.defaultprovider", requested));
            return "";
        }
        if (requested != null) {
            return requested;
        }
        String existing = options.getDefaultProviderName();
        if (merged.containsKey(existing)) {
            return existing;
        }
        return merged.keySet().stream().findFirst().orElse("");
    }

    /**
     * Uses the requested default model, else the existing one if the default provider has it, else
     * the first model of the default provider.
     */
    private static String resolveDefaultModel(
            LlmOptions options,
            Parameters parameters,
            Map<String, LlmProviderConfig> merged,
            List<String> errors) {
        LlmProviderConfig config =
                merged.get(resolveDefaultProvider(options, parameters, merged, new ArrayList<>()));
        if (config == null) {
            return "";
        }
        List<String> models = config.getModels();
        String requested = StringUtils.trimToNull(parameters.getDefaultModel());
        if (requested != null) {
            if (!models.contains(requested)) {
                errors.add(
                        Constant.messages.getString(
                                "llm.configjob.error.defaultmodel", requested, config.getName()));
            }
            return requested;
        }
        String existing = options.getDefaultModelName();
        if (models.contains(existing)) {
            return existing;
        }
        return models.stream().findFirst().orElse("");
    }
}
