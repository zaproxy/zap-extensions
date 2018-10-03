package org.zaproxy.zap.extension.AllInOneNotes;

import javax.swing.table.AbstractTableModel;
import java.util.List;
import java.util.Vector;

public class NotesTableModel extends AbstractTableModel {

    private final Vector<String> columnNames;
    private static final int COLUMN_COUNT = 2;
    private String[][] rowData;

    public NotesTableModel(List<String[]> data){
        super();

        columnNames = new Vector<>(COLUMN_COUNT);
        columnNames.add("Request ID");
        columnNames.add("Note Content");

        rowData = new String[data.size()][];
        for (int i=0; i< data.size(); i++) {
            rowData[i]= data.get(i);
        }
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
}
