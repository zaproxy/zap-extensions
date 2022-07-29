/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.zap.extension.alertFilters.automation;

import java.util.ArrayList;
import java.util.List;
import javax.swing.table.AbstractTableModel;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.alertFilters.automation.AlertFilterJob.AlertFilterData;

@SuppressWarnings("serial")
public class AlertFilterTableModel extends AbstractTableModel {

    private static final long serialVersionUID = 1L;

    private static final String[] columnNames = {
        Constant.messages.getString("alertFilters.automation.dialog.table.header.name"),
        Constant.messages.getString("alertFilters.automation.dialog.table.header.context"),
        Constant.messages.getString("alertFilters.automation.dialog.table.header.newrisk")
    };

    private List<AlertFilterData> alertFilters = new ArrayList<>();

    public AlertFilterTableModel() {
        super();
    }

    @Override
    public int getColumnCount() {
        return columnNames.length;
    }

    @Override
    public int getRowCount() {
        return alertFilters.size();
    }

    @Override
    public Object getValueAt(int row, int col) {
        AlertFilterData alertFilter = this.alertFilters.get(row);
        if (alertFilter != null) {
            switch (col) {
                case 0:
                    return alertFilter.getRuleName();
                case 1:
                    return alertFilter.getContext();
                case 2:
                    return alertFilter.getNewRisk();
                default:
                    return null;
            }
        }
        return null;
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return false;
    }

    @Override
    public String getColumnName(int col) {
        return columnNames[col];
    }

    @Override
    public Class<?> getColumnClass(int c) {
        return String.class;
    }

    public List<AlertFilterData> getAlertFilters() {
        return alertFilters;
    }

    public void setAlertFilters(List<AlertFilterData> alertFilters) {
        if (alertFilters == null) {
            this.alertFilters = new ArrayList<>();
        } else {
            this.alertFilters = alertFilters;
        }
    }

    public void clear() {
        this.alertFilters.clear();
    }

    public void add(AlertFilterData alertFilter) {
        this.alertFilters.add(alertFilter);
        this.fireTableRowsInserted(this.alertFilters.size() - 1, this.alertFilters.size() - 1);
    }

    public void update(int tableIndex, AlertFilterData alertFilter) {
        this.alertFilters.set(tableIndex, alertFilter);
        this.fireTableRowsUpdated(tableIndex, tableIndex);
    }

    public void remove(int index) {
        if (index < this.alertFilters.size()) {
            this.alertFilters.remove(index);
            this.fireTableRowsDeleted(index, index);
        }
    }
}
