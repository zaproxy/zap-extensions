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

import org.parosproxy.paros.Constant;
import org.zaproxy.zap.view.messagelocation.MessageLocationsTableModel;

public class FuzzLocationsTableModel extends MessageLocationsTableModel<FuzzLocationTableEntry> {

    private static final long serialVersionUID = 4506544561803715504L;

    private static final String[] COLUMNS = {
        Constant.messages.getString("fuzz.fuzzer.messagelocations.table.header.numberOfPayloads"),
        Constant.messages.getString("fuzz.fuzzer.messagelocations.table.header.numberOfProcessors")
    };

    public FuzzLocationsTableModel() {}

    @Override
    public String getColumnName(int column) {
        if (isLocalColumn(column)) {
            return COLUMNS[getLocalColumnIndex(column)];
        }
        return super.getColumnName(column);
    }

    @Override
    public int getColumnCount() {
        return BASE_NUMBER_OF_COLUMNS + COLUMNS.length;
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        if (isLocalColumn(columnIndex)) {
            int localColumnIndex = getLocalColumnIndex(columnIndex);
            if (localColumnIndex == 0 || localColumnIndex == 1) {
                return Integer.class;
            }
        }
        return super.getColumnClass(columnIndex);
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        if (isLocalColumn(columnIndex)) {
            int localColumnIndex = getLocalColumnIndex(columnIndex);
            if (localColumnIndex == 0) {
                return Integer.valueOf(getElement(rowIndex).getNumberOfPayloads());
            } else if (localColumnIndex == 1) {
                return Integer.valueOf(getElement(rowIndex).getProcessors().size());
            }
        }
        return super.getValueAt(rowIndex, columnIndex);
    }

    protected int getLocalColumnIndex(int columnIndex) {
        return columnIndex - BASE_NUMBER_OF_COLUMNS;
    }

    protected boolean isLocalColumn(int columnIndex) {
        return columnIndex >= BASE_NUMBER_OF_COLUMNS;
    }
}
