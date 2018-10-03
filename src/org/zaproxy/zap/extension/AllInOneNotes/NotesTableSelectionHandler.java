package org.zaproxy.zap.extension.AllInOneNotes;

import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;

import javax.swing.*;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;

public class NotesTableSelectionHandler implements ListSelectionListener {

    private ExtensionHistory _extHist;
    private JTable _noteTable;

    public NotesTableSelectionHandler(JTable noteTable, ExtensionHistory extHist){

        _extHist = extHist;
        _noteTable = noteTable;
    }

    public void valueChanged(ListSelectionEvent e) {

        if (!e.getValueIsAdjusting()) {
            int selectedRow = _noteTable.getSelectedRow();
            int noteID = Integer.parseInt((String) _noteTable.getValueAt(selectedRow, 0));
            HistoryReference hr = _extHist.getHistoryReference(noteID);
            _extHist.showInHistory(hr);
        }
    }

}
