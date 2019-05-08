/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
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
package org.zaproxy.zap.extension.portscan;

import java.awt.Component;
import java.awt.Point;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.swing.JPopupMenu;
import javax.swing.ListSelectionModel;
import javax.swing.SortOrder;
import javax.swing.table.TableModel;
import org.jdesktop.swingx.JXTable;
import org.parosproxy.paros.view.View;

public class PortScanResultsTable extends JXTable {

    private static final long serialVersionUID = -3855050766114697715L;

    public PortScanResultsTable(PortScanResultsTableModel model) {
        super(model);

        setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);

        setSortOrderCycle(SortOrder.ASCENDING, SortOrder.DESCENDING, SortOrder.UNSORTED);

        setColumnSelectionAllowed(false);
        setCellSelectionEnabled(false);
        setRowSelectionAllowed(true);
        setColumnControlVisible(true);
        setAutoCreateColumnsFromModel(false);

        setDoubleBuffered(true);

        setAutoCreateRowSorter(true);

        setComponentPopupMenu(new CustomPopupMenu());
    }

    @Override
    public void setModel(TableModel tableModel) {
        if (!(tableModel instanceof PortScanResultsTableModel)) {
            throw new IllegalArgumentException(
                    "Parameter tableModel must be a PortScanResultsTableModel.");
        }

        super.setModel(tableModel);
    }

    @Override
    public PortScanResultsTableModel getModel() {
        return (PortScanResultsTableModel) super.getModel();
    }

    public boolean isResultsSelectionEmpty() {
        return getSelectedRowCount() == 0;
    }

    public List<PortScanResultEntry> getSelectedResults() {
        final int[] rows = this.getSelectedRows();
        if (rows.length == 0) {
            return Collections.emptyList();
        }

        final List<PortScanResultEntry> results = new ArrayList<>(rows.length);
        for (int row : rows) {
            PortScanResultEntry result = getModel().getResult(convertRowIndexToModel(row));
            if (result != null) {
                results.add(result);
            }
        }
        return results;
    }

    @Override
    public Point getPopupLocation(final MouseEvent event) {
        // Hack to select the row before showing the pop up menu when invoked using the mouse.
        if (event != null) {
            final int row = rowAtPoint(event.getPoint());
            if (row < 0) {
                getSelectionModel().clearSelection();
            } else if (!getSelectionModel().isSelectedIndex(row)) {
                getSelectionModel().setSelectionInterval(row, row);
            }
        }
        return super.getPopupLocation(event);
    }

    private class CustomPopupMenu extends JPopupMenu {

        private static final long serialVersionUID = 1L;

        @Override
        public void show(Component invoker, int x, int y) {
            View.getSingleton().getPopupMenu().show(PortScanResultsTable.this, x, y);
        }
    }
}
