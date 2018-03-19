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
import java.util.List;
import org.apache.commons.configuration.HierarchicalConfiguration;
import org.parosproxy.paros.common.AbstractParam;
import org.zaproxy.zap.extension.api.ZapApiIgnore;

public class CustomPayloadsParam extends AbstractParam {

    private static final String ASCAN_ALPHA_BASE_KEY = "acanalpha";
    private static final String ALL_PAYLOADS_KEY = ASCAN_ALPHA_BASE_KEY + ".payload_list";

    private static final String PAYLOAD_ID_KEY = "id";
    private static final String PAYLOAD_KEY = "payload";
    private static final String PAYLOAD_CATEGORY_KEY = "category";
    private static final String PAYLOAD_ENABLED_KEY = "enabled";

    private static final String CONFIRM_REMOVE_PAYLOAD_KEY =
            ASCAN_ALPHA_BASE_KEY + ".confirmRemoveToken";
    private static final String NEXT_PAYLOAD_ID_KEY = ASCAN_ALPHA_BASE_KEY + ".nextPayloadId";

    private ExtensionCustomPayloads extensionCustomPayloads;
    private ArrayList<CustomPayloadModel> payloads;
    private boolean confirmRemoveToken;
    private int nextPayloadId = 1;

    public CustomPayloadsParam(ExtensionCustomPayloads extensionCustomPayloads) {
        this.extensionCustomPayloads = extensionCustomPayloads;
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
        if (payloads.size() == 0) {
            ArrayList<CustomPayloadModel> newModels = new ArrayList<>();
            for (CustomPayloadModel defaultPayload : getDefaultPayloads()) {
                CustomPayloadModel newModel = defaultPayload.clone();
                newModel.setId(nextPayloadId++);
                newModels.add(newModel);
            }
            setPayloads(newModels);
            setNextPayloadId(nextPayloadId);
        }
    }

    private void loadPayloadsFromConfig(HierarchicalConfiguration rootConfig) {
        List<HierarchicalConfiguration> fields = rootConfig.configurationsAt(ALL_PAYLOADS_KEY);
        payloads = new ArrayList<>(fields.size());
        for (HierarchicalConfiguration sub : fields) {
            int id = sub.getInt(PAYLOAD_ID_KEY);
            boolean isEnabled = sub.getBoolean(PAYLOAD_ENABLED_KEY);
            String category = sub.getString(PAYLOAD_CATEGORY_KEY, "");
            String payload = sub.getString(PAYLOAD_KEY, "");
            payloads.add(new CustomPayloadModel(id, isEnabled, category, payload));
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
        for (CustomPayloadModel payload : payloads) {
            if (maxUsedPayloadId < payload.getId()) {
                maxUsedPayloadId = payload.getId();
            }
        }
        return maxUsedPayloadId;
    }

    public List<CustomPayloadModel> getPayloads() {
        ArrayList<CustomPayloadModel> clonedPayloads = new ArrayList<>();
        for (CustomPayloadModel model : payloads) {
            clonedPayloads.add(model.clone());
        }
        return clonedPayloads;
    }

    public void setPayloads(List<CustomPayloadModel> payloads) {
        this.payloads = new ArrayList<>(payloads);
        savePayloadsToConfig();
    }

    private void savePayloadsToConfig() {
        ((HierarchicalConfiguration) getConfig()).clearTree(ALL_PAYLOADS_KEY);
        for (int i = 0, size = payloads.size(); i < size; ++i) {
            String elementBaseKey = ALL_PAYLOADS_KEY + "(" + i + ").";
            CustomPayloadModel payload = payloads.get(i);
            getConfig()
                    .setProperty(elementBaseKey + PAYLOAD_ID_KEY, Integer.valueOf(payload.getId()));
            getConfig()
                    .setProperty(
                            elementBaseKey + PAYLOAD_ENABLED_KEY,
                            Boolean.valueOf(payload.isEnabled()));
            getConfig().setProperty(elementBaseKey + PAYLOAD_CATEGORY_KEY, payload.getCategory());
            getConfig().setProperty(elementBaseKey + PAYLOAD_KEY, payload.getPayload());
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

    public List<CustomPayloadModel> getPayloadsByCategory(String category) {
        ArrayList<CustomPayloadModel> payloadsByCategory = new ArrayList<>();
        for (CustomPayloadModel payload : payloads) {
            if (payload.isEnabled() && payload.getCategory().equalsIgnoreCase(category)) {
                payloadsByCategory.add(payload);
            }
        }
        return payloadsByCategory;
    }

    public ArrayList<CustomPayloadModel> getDefaultPayloads() {
        return extensionCustomPayloads.getDefaultPayloads();
    }
}
