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
package org.zaproxy.addon.retest;

import java.util.ArrayList;
import java.util.List;
import javax.swing.table.AbstractTableModel;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;

@SuppressWarnings("serial")
public class PlanTableModel extends AbstractTableModel {

    private static final long serialVersionUID = 1L;
    private static final String[] COLUMN_NAMES = {
        Constant.messages.getString("retest.dialog.table.header.status"),
        Constant.messages.getString("retest.dialog.table.header.scanruleid"),
        Constant.messages.getString("retest.dialog.table.header.alertname"),
        Constant.messages.getString("retest.dialog.table.header.url"),
        Constant.messages.getString("retest.dialog.table.header.method"),
        Constant.messages.getString("retest.dialog.table.header.attack"),
        Constant.messages.getString("retest.dialog.table.header.param"),
        Constant.messages.getString("retest.dialog.table.header.evidence"),
        Constant.messages.getString("retest.dialog.table.header.confidence"),
        Constant.messages.getString("retest.dialog.table.header.risk"),
        Constant.messages.getString("retest.dialog.table.header.otherinfo")
    };

    private List<AlertData> rowData = new ArrayList<>();

    public PlanTableModel() {}

    @Override
    public String getColumnName(int col) {
        return COLUMN_NAMES[col];
    }

    @Override
    public int getColumnCount() {
        return COLUMN_NAMES.length;
    }

    @Override
    public int getRowCount() {
        return rowData.size();
    }

    @Override
    public Class<?> getColumnClass(int c) {
        return String.class;
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return false;
    }

    @Override
    public Object getValueAt(int row, int col) {
        AlertData alertData = rowData.get(row);
        switch (col) {
            case 0:
                return rowData.get(row).getStatus();
            case 1:
                return alertData.getScanRuleId();
            case 2:
                return alertData.getAlertName();
            case 3:
                return alertData.getUrl();
            case 4:
                return alertData.getMethod();
            case 5:
                return alertData.getAttack();
            case 6:
                return alertData.getParam();
            case 7:
                return alertData.getEvidence();
            case 8:
                return alertData.getConfidence();
            case 9:
                return alertData.getRisk();
            case 10:
                return alertData.getOtherInfo();
            default:
                return null;
        }
    }

    public List<AlertData> getAllRows() {
        return rowData;
    }

    public AlertData getRow(int row) {
        return rowData.get(row);
    }

    public void addRow(Alert newRow) {
        rowData.add(new AlertData(newRow, AlertData.Status.NOT_VERIFIED));
        fireTableRowsInserted(getRowCount() - 1, getRowCount() - 1);
    }

    public void removeRow(int rowId) {
        rowData.remove(rowId);
        fireTableRowsDeleted(rowId, rowId);
    }

    public void updateRow(int rowId, AlertData updatedRow) {
        rowData.set(rowId, updatedRow);
        fireTableRowsUpdated(rowId, rowId);
    }

    public void clear() {
        rowData.clear();
        fireTableDataChanged();
    }
}
