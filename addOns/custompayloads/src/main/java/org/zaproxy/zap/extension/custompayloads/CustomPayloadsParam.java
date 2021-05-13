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
import org.parosproxy.paros.common.AbstractParam;
import org.zaproxy.zap.extension.api.ZapApiIgnore;

public class CustomPayloadsParam extends AbstractParam {

    private static final String CUSTOM_PAYLOADS_BASE_KEY = "custompayloads";
    private static final String ALL_CATEGORIES_KEY =
            CUSTOM_PAYLOADS_BASE_KEY + ".categories.category";
    private static final String CATEGORY_NAME_KEY = "[@name]";

    private static final String PAYLOAD_ID_KEY = "id";
    private static final String PAYLOAD_KEY = "payload";
    private static final String PAYLOAD_ENABLED_KEY = "enabled";

    private static final String CONFIRM_REMOVE_PAYLOAD_KEY =
            CUSTOM_PAYLOADS_BASE_KEY + ".confirmRemoveToken";
    private static final String NEXT_PAYLOAD_ID_KEY = CUSTOM_PAYLOADS_BASE_KEY + ".nextPayloadId";

    private Map<String, PayloadCategory> payloadCategories;
    private boolean confirmRemoveToken;
    private int nextPayloadId = 1;

    public CustomPayloadsParam() {
        payloadCategories = new HashMap<>();
    }

    @Override
    protected void parse() {
        loadFromConfig();
    }

    private void loadFromConfig() {
        HierarchicalConfiguration rootConfig = (HierarchicalConfiguration) getConfig();
        loadPayloadsFromConfig(rootConfig);
        loadConfirmRemoveTokenFromConfig(rootConfig);
        loadNextPayloadIdFromConfig(rootConfig);
        initializeWithDefaultsIfPayloadsAreEmpty();
    }

    private void initializeWithDefaultsIfPayloadsAreEmpty() {
        for (PayloadCategory category : payloadCategories.values()) {
            if (category.getPayloads().isEmpty()) {
                resetDefaults(category);
            }
        }
        setNextPayloadId(nextPayloadId);
    }

    private void resetDefaults(PayloadCategory category) {
        List<CustomPayload> payloads = new ArrayList<>(category.getDefaultPayloads().size());
        for (CustomPayload defaultPayload : category.getDefaultPayloads()) {
            CustomPayload payload = defaultPayload.copy();
            payload.setId(nextPayloadId++);
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
            List<CustomPayload> payloads = new ArrayList<>();
            for (HierarchicalConfiguration sub : fields) {
                int id = sub.getInt(PAYLOAD_ID_KEY);
                boolean isEnabled = sub.getBoolean(PAYLOAD_ENABLED_KEY);
                String payload = sub.getString(PAYLOAD_KEY, "");
                payloads.add(new CustomPayload(id, isEnabled, cat, payload));
            }
            payloadCategories.put(cat, new PayloadCategory(cat, Collections.emptyList(), payloads));
        }
    }

    private void loadConfirmRemoveTokenFromConfig(HierarchicalConfiguration rootConfig) {
        confirmRemoveToken = rootConfig.getBoolean(CONFIRM_REMOVE_PAYLOAD_KEY, true);
    }

    private void loadNextPayloadIdFromConfig(HierarchicalConfiguration rootConfig) {
        int maxUsedPayloadId = getMaxUsedPayloadId();
        nextPayloadId = rootConfig.getInteger(NEXT_PAYLOAD_ID_KEY, 1);
        if (nextPayloadId <= maxUsedPayloadId) {
            setNextPayloadId(maxUsedPayloadId + 1);
        }
    }

    public int getNextPayloadId() {
        return nextPayloadId;
    }

    public void setNextPayloadId(int id) {
        nextPayloadId = id;
        saveNextPayloadId();
    }

    private void saveNextPayloadId() {
        getConfig().setProperty(NEXT_PAYLOAD_ID_KEY, Integer.valueOf(nextPayloadId));
    }

    private int getMaxUsedPayloadId() {
        int maxUsedPayloadId = 0;
        for (PayloadCategory category : payloadCategories.values()) {
            for (CustomPayload payload : category.getPayloads()) {
                if (maxUsedPayloadId < payload.getId()) {
                    maxUsedPayloadId = payload.getId();
                }
            }
        }
        return maxUsedPayloadId;
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
                                elementBaseKey + PAYLOAD_ID_KEY, Integer.valueOf(payload.getId()));
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
                .collect(Collectors.toList());
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
}
