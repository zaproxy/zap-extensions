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

public class ProcessorsTableModel
        extends AbstractMultipleOrderedOptionsBaseTableModel<PayloadProcessorTableEntry> {

    private static final long serialVersionUID = 1445590168342841316L;

    private static final String[] COLUMNS = {
        Constant.messages.getString("fuzz.fuzzer.processors.table.header.order"),
        Constant.messages.getString("fuzz.fuzzer.processors.table.header.type"),
        Constant.messages.getString("fuzz.fuzzer.processors.table.header.description")
    };

    private List<PayloadProcessorTableEntry> processors;

    public ProcessorsTableModel() {
        this.processors = new ArrayList<>();
    }

    @Override
    public int getRowCount() {
        return processors.size();
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
        PayloadProcessorTableEntry entry = getElement(rowIndex);
        if (columnIndex == 0) {
            return Integer.valueOf(entry.getOrder());
        } else if (columnIndex == 1) {
            return entry.getType();
        } else if (columnIndex == 2) {
            return entry.getDescription();
        }
        return null;
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        if (columnIndex == 0) {
            return Integer.class;
        }
        return String.class;
    }

    @Override
    public List<PayloadProcessorTableEntry> getElements() {
        return processors;
    }

    public void setProcessors(List<PayloadProcessorTableEntry> processors) {
        this.processors = new ArrayList<>(processors.size());
        for (PayloadProcessorTableEntry entry : processors) {
            this.processors.add(entry.copy());
        }
        fireTableDataChanged();
    }
}
