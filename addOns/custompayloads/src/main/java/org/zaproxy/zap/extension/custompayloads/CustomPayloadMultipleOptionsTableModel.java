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
import java.util.Set;

@SuppressWarnings("serial")
public class CustomPayloadMultipleOptionsTableModel
        extends AbstractMultipleOptionsColumnTableModel<CustomPayload> {

    private static final long serialVersionUID = 1L;
    private List<CustomPayload> defaultPayloads;
    private int nextPayloadId;

    public CustomPayloadMultipleOptionsTableModel() {
        super(CustomPayloadColumns.createColumnsForOptionsTable());
    }

    public void setDefaultPayloads(List<CustomPayload> defaultPayloads) {
        this.defaultPayloads = defaultPayloads;
    }

    public void setNextPayloadId(int nextPayloadId) {
        this.nextPayloadId = nextPayloadId;
    }

    public int getNextPayloadId() {
        return nextPayloadId;
    }

    public void resetPayloadIds() {
        nextPayloadId = 1;
        for (CustomPayload payload : getElements()) {
            setNextIdToPayload(payload);
        }
        if (this.getRowCount() > 0) {
            fireTableRowsUpdated(0, getElements().size() - 1);
        }
    }

    public void resetToDefaults() {
        clear();
        for (CustomPayload defaultPayload : defaultPayloads) {
            CustomPayload newPayload = defaultPayload.copy();
            setNextIdToPayload(newPayload);
            addModel(newPayload);
        }
    }

    public void addToTable(ArrayList<CustomPayload> payloads) {
        for (CustomPayload payload : payloads) {
            payload.setId(nextPayloadId++);
            addModel(payload);
        }
    }

    public void getPayloadsOfACategory(Set<String> payloads, String category) {
        for (CustomPayload existingPayload : getElements()) {
            if (category.equalsIgnoreCase(existingPayload.getCategory())) {
                payloads.add(existingPayload.getPayload());
            }
        }
    }

    public void setNextIdToPayload(CustomPayload payload) {
        payload.setId(nextPayloadId++);
    }

    public void addMissingDefaultPayloads() {
        for (CustomPayload defaultPayload : defaultPayloads) {
            boolean alreadyExisting = false;
            for (CustomPayload existingPayload : getElements()) {
                if (defaultPayload.getCategory().equalsIgnoreCase(existingPayload.getCategory())
                        && defaultPayload.getPayload().equals(existingPayload.getPayload())) {
                    alreadyExisting = true;
                    break;
                }
            }

            if (!alreadyExisting) {
                CustomPayload newPayload = defaultPayload.copy();
                setNextIdToPayload(newPayload);
                addModel(newPayload);
            }
        }
    }
}
