/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
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
package org.zaproxy.zap.extension.portscan;

import java.util.ArrayList;
import java.util.List;
import javax.swing.table.AbstractTableModel;
import org.parosproxy.paros.Constant;

@SuppressWarnings("serial")
public class PortScanResultsTableModel extends AbstractTableModel {

    private static final long serialVersionUID = -5470998501458271203L;

    private static final String[] COLUMN_NAMES = {
        Constant.messages.getString("ports.scan.results.table.header.port"),
        Constant.messages.getString("ports.scan.results.table.header.description")
    };

    private static final int COLUMN_COUNT = COLUMN_NAMES.length;

    private List<PortScanResultEntry> results;

    public PortScanResultsTableModel() {
        results = new ArrayList<>();
    }

    @Override
    public int getColumnCount() {
        return COLUMN_COUNT;
    }

    @Override
    public String getColumnName(int column) {
        return COLUMN_NAMES[column];
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        switch (columnIndex) {
            case 0:
                return Integer.class;
            case 1:
            default:
                return String.class;
        }
    }

    @Override
    public int getRowCount() {
        return results.size();
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        PortScanResultEntry result = results.get(rowIndex);

        switch (columnIndex) {
            case 0:
                return result.getPort();
            case 1:
                return result.getDescription();
            default:
                return "";
        }
    }

    public void addPort(int port) {
        int index = results.size();
        results.add(new PortScanResultEntry(port));

        fireTableRowsInserted(index, index);
    }

    public PortScanResultEntry getResult(int rowIndex) {
        return results.get(rowIndex);
    }

    public void clear() {
        results = new ArrayList<>();
        fireTableDataChanged();
    }
}
