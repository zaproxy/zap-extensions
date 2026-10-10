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
                LlmProviderConfig config = toConfig(name, provider, merged.get(name), errors);
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
     * Validates a single provider as it would be applied to the existing options.
     *
     * @param deleteExisting if the existing providers would be deleted before the provider is
     *     applied, in which case it can not be a partial update of one of them
     */
    static List<String> validate(LlmOptions options, Provider provider, boolean deleteExisting) {
        List<String> errors = new ArrayList<>();
        String name = StringUtils.trimToEmpty(provider.getName());
        if (name.isEmpty()) {
            errors.add(Constant.messages.getString("llm.configjob.error.name"));
        } else {
            toConfig(
                    name,
                    provider,
                    deleteExisting ? null : options.getProviderConfig(name),
                    errors);
        }
        return errors;
    }

    private static LlmProviderConfig toConfig(
            String name, Provider provider, LlmProviderConfig existing, List<String> errors) {
        LlmProvider type = provider.getType();
        if (type == null && existing != null) {
            type = existing.getProvider();
        }
        if (type == null || type == LlmProvider.NONE) {
            errors.add(Constant.messages.getString("llm.configjob.error.type", name));
            return null;
        }

        LlmProviderConfig config =
                existing != null
                        ? new LlmProviderConfig(existing)
                        : new LlmProviderConfig(name, type, "", "", List.of());
        boolean typeChanged = existing != null && existing.getProvider() != type;
        config.setProvider(type);
        if (typeChanged) {
            config.setTrusted(type.isTrustedByDefault());
        }
        if (provider.getApiKey() != null) {
            config.setApiKey(provider.getApiKey());
        }
        if (provider.getEndpoint() != null) {
            config.setEndpoint(provider.getEndpoint());
        }
        if (provider.getModels() != null) {
            config.setModels(
                    provider.getModels().stream()
                            .map(StringUtils::trimToNull)
                            .filter(Objects::nonNull)
                            .toList());
        }
        if (provider.getTrusted() != null) {
            config.setTrusted(provider.getTrusted());
        }
        if (provider.getTimeout() != null) {
            config.setTimeoutSeconds(provider.getTimeout());
        }

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
