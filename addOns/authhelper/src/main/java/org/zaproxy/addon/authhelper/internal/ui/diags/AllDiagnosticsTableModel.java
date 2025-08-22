/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
package org.zaproxy.addon.authhelper.internal.ui.diags;

import java.util.ArrayList;
import java.util.List;
import javax.swing.table.AbstractTableModel;
import org.parosproxy.paros.Constant;

@SuppressWarnings("serial")
public class AllDiagnosticsTableModel extends AbstractTableModel {

    private static final long serialVersionUID = 5446781970087315105L;

    private static final String[] COLUMNS = {
        Constant.messages.getString("authhelper.authdiags.panel.table.header.timestamp"),
        Constant.messages.getString("authhelper.authdiags.panel.table.header.id"),
        Constant.messages.getString("authhelper.authdiags.panel.table.header.method"),
        Constant.messages.getString("authhelper.authdiags.panel.table.header.context"),
        Constant.messages.getString("authhelper.authdiags.panel.table.header.user"),
        Constant.messages.getString("authhelper.authdiags.panel.table.header.url"),
        Constant.messages.getString("authhelper.authdiags.panel.table.header.script"),
        Constant.messages.getString("authhelper.authdiags.panel.table.header.steps"),
    };

    private List<DiagnosticUi> entries;

    public AllDiagnosticsTableModel() {
        entries = new ArrayList<>();
    }

    public DiagnosticUi getDiagnostic(int row) {
        return entries.get(row);
    }

    public void setEntries(List<DiagnosticUi> entries) {
        this.entries = new ArrayList<>(entries);
        fireTableDataChanged();
    }

    public void clear() {
        entries.clear();
        fireTableDataChanged();
    }

    public void addEntry(DiagnosticUi entry) {
        int rowIndex = entries.size();
        entries.add(entry);
        fireTableRowsInserted(rowIndex, rowIndex);
    }

    public DiagnosticUi remove(int rowIndex) {
        DiagnosticUi diag = entries.remove(rowIndex);
        fireTableRowsDeleted(rowIndex, rowIndex);
        return diag;
    }

    @Override
    public String getColumnName(int column) {
        return COLUMNS[column];
    }

    @Override
    public int getColumnCount() {
        return COLUMNS.length;
    }

    @Override
    public int getRowCount() {
        return entries.size();
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        DiagnosticUi diagnostic = entries.get(rowIndex);
        switch (columnIndex) {
            case 0:
                return diagnostic.getCreateTimestamp();
            case 1:
                return diagnostic.getId();
            case 2:
                return diagnostic.getAuthenticationMethod();
            case 3:
                return diagnostic.getContext();
            case 4:
                return diagnostic.getUser();
            case 5:
                return diagnostic.getUrl();
            case 6:
                return diagnostic.getScript() != null;
            case 7:
                return diagnostic.getSteps();
            default:
                return "";
        }
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        switch (columnIndex) {
            case 1, 7:
                return Integer.class;
            case 6:
                return Boolean.class;
            default:
                return String.class;
        }
    }
}
