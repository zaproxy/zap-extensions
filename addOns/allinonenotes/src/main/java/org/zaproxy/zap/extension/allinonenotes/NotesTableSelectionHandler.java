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

import javax.swing.JTable;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;

public class NotesTableSelectionHandler implements ListSelectionListener {

    private ExtensionHistory _extHist;
    private JTable _noteTable;

    public NotesTableSelectionHandler(JTable noteTable, ExtensionHistory extHist) {

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
