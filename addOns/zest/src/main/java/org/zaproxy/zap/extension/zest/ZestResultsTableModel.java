/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2013 The ZAP Development Team
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
package org.zaproxy.zap.extension.zest;

import java.awt.EventQueue;
import java.util.ArrayList;
import java.util.List;
import java.util.Map.Entry;
import java.util.SortedMap;
import java.util.TreeMap;
import javax.swing.Icon;
import javax.swing.ImageIcon;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.view.table.AbstractCustomColumnHistoryReferencesTableModel;
import org.zaproxy.zap.view.table.AbstractHistoryReferencesTableEntry;
import org.zaproxy.zap.view.table.DefaultHistoryReferencesTableEntry;

@SuppressWarnings("serial")
public class ZestResultsTableModel
        extends AbstractCustomColumnHistoryReferencesTableModel<
                ZestResultsTableModel.ZestResultsTableEntry> {

    private static final long serialVersionUID = 1L;

    private static final String RESULT_COLUMN_NAME =
            Constant.messages.getString("zest.results.table.header.result");

    private List<ZestResultsTableEntry> results;
    private SortedMap<Integer, Integer> historyIdToRow;

    public ZestResultsTableModel() {
        super(
                new Column[] {
                    Column.HREF_ID,
                    Column.METHOD,
                    Column.URL,
                    Column.STATUS_CODE,
                    Column.STATUS_REASON,
                    Column.RTT,
                    Column.SIZE_RESPONSE_BODY,
                    Column.CUSTOM,
                    Column.CUSTOM
                });

        results = new ArrayList<>();
        historyIdToRow = new TreeMap<>();
    }

    @Override
    public void clear() {
        if (View.isInitialised() && !EventQueue.isDispatchThread()) {
            EventQueue.invokeLater(this::clear);
            return;
        }

        results = new ArrayList<>();
        historyIdToRow = new TreeMap<>();

        fireTableDataChanged();
    }

    @Override
    public int getRowCount() {
        return results.size();
    }

    @Override
    protected Class<?> getColumnClass(Column column) {
        return AbstractHistoryReferencesTableEntry.getColumnClass(column);
    }

    @Override
    protected Object getPrototypeValue(Column column) {
        return AbstractHistoryReferencesTableEntry.getPrototypeValue(column);
    }

    @Override
    protected Object getCustomValueAt(ZestResultsTableEntry zrw, int columnIndex) {
        switch (getCustomColumnIndex(columnIndex)) {
            case 0:
                return zrw.getIcon();
            case 1:
                return zrw.getMessage();
        }
        return null;
    }

    @Override
    protected String getCustomColumnName(int columnIndex) {
        switch (getCustomColumnIndex(columnIndex)) {
            case 0:
                return "";
            case 1:
                return RESULT_COLUMN_NAME;
        }
        return null;
    }

    @Override
    protected Class<?> getCustomColumnClass(int columnIndex) {
        switch (getCustomColumnIndex(columnIndex)) {
            case 0:
                return Icon.class;
            case 1:
                return String.class;
        }
        return null;
    }

    @Override
    protected Object getCustomPrototypeValue(int columnIndex) {
        if (getCustomColumnIndex(columnIndex) == 1) {
            return "Some long message with some long text and variable length";
        }
        return null;
    }

    public void add(ZestResultWrapper href) {
        addEntry(new ZestResultsTableEntry(href, getColumns()));
    }

    @Override
    public void addEntry(final ZestResultsTableEntry entry) {
        if (View.isInitialised() && !EventQueue.isDispatchThread()) {
            EventQueue.invokeLater(() -> addEntry(entry));
            return;
        }

        int index = results.size();
        results.add(entry);
        historyIdToRow.put(entry.getHistoryId(), Integer.valueOf(index));
        fireTableRowsInserted(index, index);
    }

    @Override
    public void refreshEntryRow(int historyReferenceId) {
        // Nothing to do.
    }

    @Override
    public void removeEntry(int historyReferenceId) {
        Integer key = Integer.valueOf(historyReferenceId);
        Integer row = historyIdToRow.get(key);
        if (row != null) {
            final int rowIndex = row.intValue();

            results.remove(rowIndex);
            historyIdToRow.remove(key);

            for (Entry<Integer, Integer> mapping :
                    historyIdToRow
                            .subMap(
                                    Integer.valueOf(key.intValue() + 1),
                                    Integer.valueOf(Integer.MAX_VALUE))
                            .entrySet()) {
                mapping.setValue(Integer.valueOf(mapping.getValue().intValue() - 1));
            }

            fireTableRowsDeleted(rowIndex, rowIndex);
        }
    }

    @Override
    public ZestResultsTableEntry getEntry(int rowIndex) {
        return results.get(rowIndex);
    }

    @Override
    public ZestResultsTableEntry getEntryWithHistoryId(int historyReferenceId) {
        final int row = getEntryRowIndex(historyReferenceId);
        if (row != -1) {
            return results.get(row);
        }
        return null;
    }

    @Override
    public int getEntryRowIndex(int historyReferenceId) {
        final Integer row = historyIdToRow.get(Integer.valueOf(historyReferenceId));
        if (row != null) {
            return row.intValue();
        }
        return -1;
    }

    public ZestResultWrapper getHistoryReference(int row) {
        return getEntry(row).getHistoryReference();
    }

    public int getIndex(HttpMessage message) {
        for (int i = 0; i < results.size(); i++) {
            ZestResultWrapper zrw = getHistoryReference(i);
            try {
                if (zrw.getHttpMessage().getHistoryRef() != null
                        && message.getHistoryRef() != null) {
                    if (zrw.getHttpMessage().getHistoryRef().getHistoryId()
                            == message.getHistoryRef().getHistoryId()) {
                        return i;
                    }
                }
            } catch (HttpMalformedHeaderException | DatabaseException e) {
                // Ignore
            }
        }
        return -1;
    }

    public static class ZestResultsTableEntry extends DefaultHistoryReferencesTableEntry {

        private static final Icon SCAN_ACTION =
                new ImageIcon(ZAP.class.getResource("/resource/icon/16/093.png")); // Flame

        private static final Icon PASSED =
                new ImageIcon(ZAP.class.getResource("/resource/icon/16/102.png")); // Green tick
        private static final Icon FAILED =
                new ImageIcon(ZAP.class.getResource("/resource/icon/16/101.png")); // Red cross

        private Icon icon;

        private String message;

        public ZestResultsTableEntry(ZestResultWrapper zrw, Column[] columns) {
            super(zrw, columns);

            if (zrw.getType().equals(ZestResultWrapper.Type.scanAction)) {
                icon = SCAN_ACTION;
            } else if (zrw.isPassed()) {
                icon = PASSED;
            } else {
                icon = FAILED;
            }

            this.message = zrw.getMessage();
        }

        @Override
        public ZestResultWrapper getHistoryReference() {
            return (ZestResultWrapper) super.getHistoryReference();
        }

        public Icon getIcon() {
            return icon;
        }

        public String getMessage() {
            return message;
        }

        public void setMessage(String msg) {
            message = msg;
        }

        public void setPassed(boolean passed) {
            if (passed) {
                icon = PASSED;
            } else {
                icon = FAILED;
            }
        }
    }
}
