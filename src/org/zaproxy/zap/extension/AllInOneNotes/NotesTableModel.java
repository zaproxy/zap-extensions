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
package org.zaproxy.zap.extension.AllInOneNotes;

import org.parosproxy.paros.Constant;
import javax.swing.table.AbstractTableModel;
import java.util.List;
import java.util.Vector;

public class NotesTableModel extends AbstractTableModel {

    private static final String PREFIX = "allInOneNotes";
    private static final long serialVersionUID = 555559948904951733L;
    private final Vector<String> columnNames;
    private static final int COLUMN_COUNT = 2;
    private String[][] rowData = new String[0][];

    public NotesTableModel(){
        super();

        columnNames = new Vector<>(COLUMN_COUNT);
        columnNames.add(Constant.messages.getString(PREFIX + ".columnHeaders.requestId"));
        columnNames.add(Constant.messages.getString(PREFIX + ".columnHeaders.noteContent"));
    };

    @Override
    public String getColumnName(int col) {
        return columnNames.get(col);
    }

    @Override
    public int getRowCount() { return rowData.length; }

    @Override
    public int getColumnCount() { return columnNames.size(); }

    @Override
    public Object getValueAt(int row, int col) {
        return rowData[row][col];
    }

    public boolean isCellEditable(int row, int col)
    { return false; }

    public void setValueAt(Object value, int row, int col) {
        rowData[row][col] = value.toString();
        fireTableCellUpdated(row, col);
    }

    public void addRow(String[] newRow){

        int prevRowCount = getRowCount();
        String[][] tempRowData = new String[prevRowCount+1][];

        for (int i=0; i< prevRowCount; i++) {
            tempRowData[i]= rowData[i];
        }

        tempRowData[prevRowCount] = newRow;
        rowData = tempRowData;
        fireTableRowsInserted(prevRowCount, prevRowCount);

    }

    public void removeRow(int rowId){

        int prevRowCount = getRowCount();
        String[][] tempRowData = new String[prevRowCount-1][];

        int counter = 0;
        for (int i=0; i< prevRowCount; i++) {
            if (i != rowId){
                tempRowData[counter]= rowData[i];
                counter++;
            }
        }

        rowData = tempRowData;
        fireTableRowsDeleted(rowId, rowId);

    }
}
