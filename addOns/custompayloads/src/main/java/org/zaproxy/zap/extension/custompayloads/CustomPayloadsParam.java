/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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
package org.zaproxy.zap.extension.custompayloads;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.apache.commons.configuration.HierarchicalConfiguration;
import org.zaproxy.zap.common.VersionedAbstractParam;
import org.zaproxy.zap.extension.api.ZapApiIgnore;

public class CustomPayloadsParam extends VersionedAbstractParam {

    /**
     * The current version of the configurations. Used to keep track of configuration changes
     * between releases, in case changes/updates are needed.
     *
     * <p>It only needs to be incremented for configuration changes (not releases of the add-on).
     *
     * @see #CONFIG_VERSION_KEY
     * @see #updateConfigsImpl(int)
     */
    private static final int CURRENT_CONFIG_VERSION = 1;

    protected static final String CUSTOM_PAYLOADS_BASE_KEY = "custompayloads";

    /**
     * The key for the version of the configurations.
     *
     * @see #CURRENT_CONFIG_VERSION
     */
    protected static final String CONFIG_VERSION_KEY = CUSTOM_PAYLOADS_BASE_KEY + VERSION_ATTRIBUTE;

    protected static final String ALL_CATEGORIES_KEY =
            CUSTOM_PAYLOADS_BASE_KEY + ".categories.category";
    protected static final String CATEGORY_NAME_KEY = "[@name]";

    protected static final String PAYLOAD_KEY = "payload";
    protected static final String PAYLOAD_ENABLED_KEY = "enabled";

    protected static final String CONFIRM_REMOVE_PAYLOAD_KEY =
            CUSTOM_PAYLOADS_BASE_KEY + ".confirmRemoveToken";

    private Map<String, PayloadCategory> payloadCategories;
    private boolean confirmRemoveToken;

    public CustomPayloadsParam() {
        payloadCategories = new HashMap<>();
    }

    private void initializeWithDefaultsIfPayloadsAreEmpty() {
        for (PayloadCategory category : payloadCategories.values()) {
            if (category.getPayloads().isEmpty()) {
                resetDefaults(category);
            }
        }
    }

    private static void resetDefaults(PayloadCategory category) {
        List<CustomPayload> payloads = new ArrayList<>(category.getDefaultPayloads().size());
        for (CustomPayload defaultPayload : category.getDefaultPayloads()) {
            CustomPayload payload = defaultPayload.copy();
            payloads.add(payload);
        }
        category.setPayloads(payloads);
    }

    private void loadPayloadsFromConfig(HierarchicalConfiguration rootConfig) {
        List<HierarchicalConfiguration> categories =
                rootConfig.configurationsAt(ALL_CATEGORIES_KEY);
        payloadCategories = new HashMap<>();
        for (HierarchicalConfiguration category : categories) {
            List<HierarchicalConfiguration> fields = category.configurationsAt("payloads.payload");
            String cat = category.getString(CATEGORY_NAME_KEY);
            if (cat == null) {
                continue;
            }
            List<CustomPayload> payloads = new ArrayList<>();
            for (HierarchicalConfiguration sub : fields) {
                boolean isEnabled = sub.getBoolean(PAYLOAD_ENABLED_KEY);
                String payload = sub.getString(PAYLOAD_KEY, "");
                payloads.add(new CustomPayload(isEnabled, cat, payload));
            }
            payloadCategories.put(cat, new PayloadCategory(cat, Collections.emptyList(), payloads));
        }
    }

    private void loadConfirmRemoveTokenFromConfig(HierarchicalConfiguration rootConfig) {
        confirmRemoveToken = rootConfig.getBoolean(CONFIRM_REMOVE_PAYLOAD_KEY, true);
    }

    public List<CustomPayload> getPayloads() {
        ArrayList<CustomPayload> clonedPayloads = new ArrayList<>();
        for (PayloadCategory category : payloadCategories.values()) {
            for (CustomPayload payload : category.getPayloads()) {
                clonedPayloads.add(payload.copy());
            }
        }
        return clonedPayloads;
    }

    public void setPayloads(List<CustomPayload> payloads) {
        Map<String, List<CustomPayload>> newPayloads =
                payloads.stream()
                        .collect(
                                Collectors.groupingBy(
                                        CustomPayload::getCategory,
                                        Collectors.mapping(
                                                Function.identity(), Collectors.toList())));

        payloadCategories.forEach(
                (name, category) ->
                        category.setPayloads(
                                newPayloads.getOrDefault(name, Collections.emptyList())));
        savePayloadsToConfig();
    }

    private void savePayloadsToConfig() {
        ((HierarchicalConfiguration) getConfig()).clearTree(ALL_CATEGORIES_KEY);
        int catIdx = 0;
        for (PayloadCategory category : payloadCategories.values()) {
            String catElementBaseKey = ALL_CATEGORIES_KEY + "(" + catIdx + ")";
            List<CustomPayload> payloads = category.getPayloads();
            getConfig().setProperty(catElementBaseKey + CATEGORY_NAME_KEY, category.getName());
            for (int i = 0, size = payloads.size(); i < size; ++i) {
                String elementBaseKey =
                        catElementBaseKey + ".payloads." + PAYLOAD_KEY + "(" + i + ").";
                CustomPayload payload = payloads.get(i);
                getConfig()
                        .setProperty(
                                elementBaseKey + PAYLOAD_ENABLED_KEY,
                                Boolean.valueOf(payload.isEnabled()));
                getConfig().setProperty(elementBaseKey + PAYLOAD_KEY, payload.getPayload());
            }
            catIdx++;
        }
    }

    @ZapApiIgnore
    public boolean isConfirmRemoveToken() {
        return this.confirmRemoveToken;
    }

    @ZapApiIgnore
    public void setConfirmRemoveToken(boolean confirmRemove) {
        this.confirmRemoveToken = confirmRemove;
        saveConfirmRemoveToken();
    }

    private void saveConfirmRemoveToken() {
        getConfig().setProperty(CONFIRM_REMOVE_PAYLOAD_KEY, Boolean.valueOf(confirmRemoveToken));
    }

    public List<CustomPayload> getDefaultPayloads() {
        return payloadCategories.values().stream()
                .map(PayloadCategory::getDefaultPayloads)
                .flatMap(List::stream)
                .toList();
    }

    public Collection<String> getCategoriesNames() {
        return Collections.unmodifiableSet(payloadCategories.keySet());
    }

    public void addPayloadCategory(PayloadCategory payloadCategory) {
        payloadCategories.compute(
                payloadCategory.getName(),
                (name, category) -> {
                    boolean setDefaults = true;
                    if (category != null) {
                        if (!category.getPayloads().isEmpty()) {
                            payloadCategory.setPayloads(category.getPayloads());
                            setDefaults = false;
                        }
                    }
                    if (setDefaults) {
                        resetDefaults(payloadCategory);
                    }
                    return payloadCategory;
                });
    }

    public void removePayloadCategory(PayloadCategory payloadCategory) {
        payloadCategories.compute(
                payloadCategory.getName(),
                (name, category) -> {
                    if (category != null) {
                        return new PayloadCategory(
                                name, Collections.emptyList(), payloadCategory.getPayloads());
                    }
                    return null;
                });
    }

    @Override
    protected void parseImpl() {
        HierarchicalConfiguration rootConfig = (HierarchicalConfiguration) getConfig();
        loadPayloadsFromConfig(rootConfig);
        loadConfirmRemoveTokenFromConfig(rootConfig);
        initializeWithDefaultsIfPayloadsAreEmpty();
    }

    @Override
    protected int getCurrentVersion() {
        return CURRENT_CONFIG_VERSION;
    }

    @Override
    protected String getConfigVersionKey() {
        return CONFIG_VERSION_KEY;
    }

    @Override
    @SuppressWarnings("fallthrough")
    protected void updateConfigsImpl(int fileVersion) {
        switch (fileVersion) {
            case NO_CONFIG_VERSION:
                getConfig().clearProperty(CUSTOM_PAYLOADS_BASE_KEY + ".nextPayloadId");
                getConfig().clearProperty("custompayloads.categories.category.payloads.payload.id");
            default:
        }
    }
}
