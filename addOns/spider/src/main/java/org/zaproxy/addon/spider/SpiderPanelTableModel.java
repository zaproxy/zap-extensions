/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2012 The ZAP Development Team
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
package org.zaproxy.addon.spider;

import java.util.ArrayList;
import java.util.List;
import javax.swing.event.TableModelListener;
import javax.swing.table.TableModel;

import ca.odell.glazedlists.BasicEventList;
import ca.odell.glazedlists.EventList;
import ca.odell.glazedlists.gui.TableFormat;
import ca.odell.glazedlists.swing.AdvancedTableModel;
import ca.odell.glazedlists.util.concurrent.Lock;
import org.parosproxy.paros.Constant;

import static ca.odell.glazedlists.swing.GlazedListsSwing.eventTableModelWithThreadProxyList;

/** The Class HttpSessionsTableModel that is used as a TableModel for the Http Sessions Panel. */
public class SpiderPanelTableModel implements TableModel {
    private static final String[] COLUMN_NAMES = {
        Constant.messages.getString("spider.table.header.inScope"),
        Constant.messages.getString("spider.table.header.method"),
        Constant.messages.getString("spider.table.header.uri"),
        Constant.messages.getString("spider.table.header.flags")
    };

    private static final int COLUMN_COUNT = COLUMN_NAMES.length;

    private final EventList<SpiderScanResult> scanResults = new BasicEventList<>();
    private final AdvancedTableModel<SpiderScanResult> tableModel = eventTableModelWithThreadProxyList(
            scanResults, new ScanResultTableFormat());

    private final boolean incFlags;

    /** Instantiates a new spider panel table model. */
    public SpiderPanelTableModel() {
        this(true);
    }

    /** Instantiates a new spider panel table model. */
    public SpiderPanelTableModel(boolean incFlags) {
        this.incFlags = incFlags;
    }

    public class ScanResultTableFormat implements TableFormat<SpiderScanResult> {
        @Override
        public String getColumnName(int column) {
            return COLUMN_NAMES[column];
        }

        @Override
        public int getColumnCount() {
            if (incFlags) {
                return COLUMN_COUNT;
            } else {
                return COLUMN_COUNT - 1;
            }
        }

        @Override
        public Object getColumnValue(SpiderScanResult result, int col) {
            // Get the ScanResult and the required field
            return switch (col) {
                case 0 -> result.processed;
                case 1 -> result.method;
                case 2 -> result.uri;
                case 3 -> result.flags;
                default -> null;
            };
        }
    }

    /** can be called on any thread **/
    public void removeAllElements() {
        withWriteLock(scanResults::clear);
    }

    /** can be called on any thread **/
    public void addScanResult(String uri, String method, String flags, boolean skipped) {
        withWriteLock(() -> scanResults.add(new SpiderScanResult(uri, method, flags, !skipped)));
    }

    private void withWriteLock(Runnable r) {
        Lock lock = scanResults.getReadWriteLock().writeLock();
        lock.lock();
        try {
            r.run();
        }
        finally {
            lock.unlock();
        }
    }


    public record SpiderScanResult(String uri, String method, String flags, boolean processed) {

    }

    @Override
    public void removeTableModelListener(TableModelListener l) {
        tableModel.removeTableModelListener(l);
    }

    @Override
    public void addTableModelListener(TableModelListener l) {
        tableModel.addTableModelListener(l);
    }

    @Override
    public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
        tableModel.setValueAt(aValue, rowIndex, columnIndex);
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        return tableModel.getValueAt(rowIndex, columnIndex);
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return tableModel.isCellEditable(rowIndex, columnIndex);
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return tableModel.getColumnClass(columnIndex);
    }

    @Override
    public String getColumnName(int columnIndex) {
        return tableModel.getColumnName(columnIndex);
    }

    @Override
    public int getColumnCount() {
        return tableModel.getColumnCount();
    }

    @Override
    public int getRowCount() {
        return tableModel.getRowCount();
    }

    public List<String> getAddedNodes() {
        List<String> list = new ArrayList<>(this.scanResults.size());
        for (SpiderScanResult res : this.scanResults) {
            list.add(res.uri);
        }
        return list;
    }
}
