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
import org.zaproxy.zap.extension.fuzz.FuzzerMessageProcessor;
import org.zaproxy.zap.extension.fuzz.FuzzerMessageProcessorUI;
import org.zaproxy.zap.extension.httppanel.Message;
import org.zaproxy.zap.view.AbstractMultipleOrderedOptionsBaseTableModel;

public class FuzzerMessageProcessorsTableModel<
                T1 extends Message,
                T2 extends FuzzerMessageProcessor<T1>,
                T3 extends FuzzerMessageProcessorUI<T1, T2>>
        extends AbstractMultipleOrderedOptionsBaseTableModel<
                FuzzerMessageProcessorTableEntry<T1, T2>> {

    private static final long serialVersionUID = 1445590168342841316L;

    private static final String[] COLUMNS = {
        Constant.messages.getString("fuzz.fuzzer.messageprocessors.table.header.order"),
        Constant.messages.getString("fuzz.fuzzer.messageprocessors.table.header.name"),
        Constant.messages.getString("fuzz.fuzzer.messageprocessors.table.header.description")
    };

    private List<FuzzerMessageProcessorTableEntry<T1, T2>> messageProcessors;

    public FuzzerMessageProcessorsTableModel(List<T3> messageProcessors) {
        this.messageProcessors = new ArrayList<>(messageProcessors.size());
        for (FuzzerMessageProcessorUI<T1, T2> processor : messageProcessors) {
            this.messageProcessors.add(
                    new FuzzerMessageProcessorTableEntry<>(
                            this.messageProcessors.size() + 1, processor));
        }
    }

    @Override
    public int getRowCount() {
        return messageProcessors.size();
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
        FuzzerMessageProcessorTableEntry<T1, T2> payloadTableEntry = getElement(rowIndex);
        if (columnIndex == 0) {
            return Integer.valueOf(payloadTableEntry.getOrder());
        } else if (columnIndex == 1) {
            return payloadTableEntry.getName();
        } else if (columnIndex == 2) {
            return payloadTableEntry.getDescription();
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
    public List<FuzzerMessageProcessorTableEntry<T1, T2>> getElements() {
        return messageProcessors;
    }
}
