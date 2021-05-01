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
package org.zaproxy.zap.extension.allinonenotes;

import java.util.ArrayList;
import java.util.List;
import javax.swing.table.AbstractTableModel;
import org.parosproxy.paros.Constant;

public class NotesTableModel extends AbstractTableModel {

    private static final String PREFIX = "allinonenotes";
    private static final long serialVersionUID = 555559948904951733L;
    private final List<String> columnNames;
    private static final int COLUMN_COUNT = 2;
    private List<NoteRecord> rowData = new ArrayList<>();

    public NotesTableModel() {
        super();

        columnNames = new ArrayList<>(COLUMN_COUNT);
        columnNames.add(Constant.messages.getString(PREFIX + ".columnHeaders.requestId"));
        columnNames.add(Constant.messages.getString(PREFIX + ".columnHeaders.noteContent"));
    }

    @Override
    public String getColumnName(int col) {
        return columnNames.get(col);
    }

    @Override
    public int getRowCount() {
        return rowData.size();
    }

    @Override
    public int getColumnCount() {
        return columnNames.size();
    }

    @Override
    public Object getValueAt(int rowIdx, int colIdx) {
        NoteRecord row = rowData.get(rowIdx);
        switch (colIdx) {
            case 0:
                return row.getMessageId();
            case 1:
                return row.getNote();
            default:
                return null;
        }
    }

    @Override
    public boolean isCellEditable(int row, int col) {
        return false;
    }

    @Override
    public void setValueAt(Object value, int rowIdx, int colIdx) {
        switch (colIdx) {
            case 0:
                rowData.get(rowIdx).setMessageId((int) value);
                break;
            case 1:
                rowData.get(rowIdx).setNote(value.toString());
                break;
        }
        fireTableCellUpdated(rowIdx, colIdx);
    }

    public NoteRecord getRow(int number) {
        return rowData.get(number);
    }

    public void addRow(NoteRecord newRow) {
        rowData.add(newRow);
        fireTableRowsInserted(getRowCount() - 1, getRowCount() - 1);
    }

    public void removeRow(int rowId) {
        rowData.remove(rowId);
        fireTableRowsDeleted(rowId, rowId);
    }

    public void clear() {
        rowData.clear();
        fireTableDataChanged();
    }
}
