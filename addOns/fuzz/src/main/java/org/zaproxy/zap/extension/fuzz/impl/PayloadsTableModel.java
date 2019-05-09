/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2015 The ZAP Development Team
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
package org.zaproxy.zap.extension.fuzz.impl;

import java.util.ArrayList;
import java.util.List;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.view.AbstractMultipleOrderedOptionsBaseTableModel;

public class PayloadsTableModel
        extends AbstractMultipleOrderedOptionsBaseTableModel<PayloadTableEntry> {

    private static final long serialVersionUID = 1445590168342841316L;

    private static final String[] COLUMNS = {
        Constant.messages.getString("fuzz.fuzzer.payloads.table.header.order"),
        Constant.messages.getString("fuzz.fuzzer.payloads.table.header.type"),
        Constant.messages.getString("fuzz.fuzzer.payloads.table.header.description"),
        Constant.messages.getString("fuzz.fuzzer.payloads.table.header.numberOfProcessors")
    };

    private List<PayloadTableEntry> payloads;

    public PayloadsTableModel(List<PayloadTableEntry> payloads) {
        this.payloads = new ArrayList<>(payloads.size());
        for (PayloadTableEntry entry : payloads) {
            this.payloads.add(entry.copy());
        }
    }

    public PayloadsTableModel() {
        this.payloads = new ArrayList<>();
    }

    @Override
    public int getRowCount() {
        return payloads.size();
    }

    @Override
    public int getColumnCount() {
        return COLUMNS.length;
    }

    @Override
    public String getColumnName(int column) {
        return COLUMNS[column];
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        PayloadTableEntry payloadTableEntry = getElement(rowIndex);
        if (columnIndex == 0) {
            return Integer.valueOf(payloadTableEntry.getOrder());
        } else if (columnIndex == 1) {
            return payloadTableEntry.getType();
        } else if (columnIndex == 2) {
            return payloadTableEntry.getDescription();
        } else if (columnIndex == 3) {
            return Integer.valueOf(payloadTableEntry.getPayloadProcessors().size());
        }
        return null;
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        if (columnIndex == 0 || columnIndex == 3) {
            return Integer.class;
        }
        return String.class;
    }

    @Override
    public List<PayloadTableEntry> getElements() {
        return payloads;
    }

    public void setElements(List<PayloadTableEntry> payloads) {
        this.payloads = new ArrayList<>(payloads.size());
        for (PayloadTableEntry entry : payloads) {
            this.payloads.add(entry.copy());
        }
        fireTableDataChanged();
    }
}
