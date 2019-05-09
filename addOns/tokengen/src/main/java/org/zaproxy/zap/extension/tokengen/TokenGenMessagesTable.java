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
package org.zaproxy.zap.extension.tokengen;

import java.awt.Component;
import java.util.Date;
import javax.swing.JPopupMenu;
import javax.swing.ListSelectionModel;
import javax.swing.SortOrder;
import javax.swing.table.TableModel;
import org.jdesktop.swingx.JXTable;
import org.jdesktop.swingx.renderer.DefaultTableRenderer;
import org.jdesktop.swingx.table.ColumnFactory;
import org.jdesktop.swingx.table.TableColumnExt;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.view.ZapTable;
import org.zaproxy.zap.view.renderer.DateFormatStringValue;
import org.zaproxy.zap.view.renderer.SizeBytesStringValue;
import org.zaproxy.zap.view.renderer.TimeDurationStringValue;

public class TokenGenMessagesTable extends ZapTable {

    private static final long serialVersionUID = -5288994159508971262L;

    private static final TokenGetMessagesTableColumnFactory DEFAULT_COLUMN_FACTORY =
            new TokenGetMessagesTableColumnFactory();

    /**
     * The maximum number of rows that should be taken into account when doing row related
     * configurations (for example, pack all columns).
     *
     * @see #packAll()
     */
    private static final int MAX_CONFIG_ROW_COUNT = 500;

    public TokenGenMessagesTable(TokenGenMessagesTableModel model) {
        super(model);

        setColumnFactory(DEFAULT_COLUMN_FACTORY);
        createDefaultColumnsFromModel();
        initializeColumnWidths();

        setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);

        setSortOrderCycle(SortOrder.ASCENDING, SortOrder.DESCENDING, SortOrder.UNSORTED);

        setColumnSelectionAllowed(false);
        setCellSelectionEnabled(false);
        setRowSelectionAllowed(true);

        setAutoCreateRowSorter(true);

        setComponentPopupMenu(new CustomPopupMenu());
    }

    @Override
    protected void createDefaultRenderers() {
        super.createDefaultRenderers();

        setDefaultRenderer(Date.class, new DefaultTableRenderer(new DateFormatStringValue()));
    }

    @Override
    public void setModel(TableModel tableModel) {
        if (!(tableModel instanceof TokenGenMessagesTableModel)) {
            throw new IllegalArgumentException(
                    "Parameter tableModel must be a TokenGenMessagesTableModel.");
        }

        super.setModel(tableModel);
    }

    @Override
    public TokenGenMessagesTableModel getModel() {
        return (TokenGenMessagesTableModel) super.getModel();
    }

    protected static class TokenGetMessagesTableColumnFactory extends ColumnFactory {

        public TokenGetMessagesTableColumnFactory() {}

        @Override
        protected int getRowCount(final JXTable table) {
            final int rowCount = super.getRowCount(table);
            if (rowCount > MAX_CONFIG_ROW_COUNT) {
                return MAX_CONFIG_ROW_COUNT;
            }
            return rowCount;
        }

        @Override
        public void configureTableColumn(final TableModel model, final TableColumnExt columnExt) {
            super.configureTableColumn(model, columnExt);

            if (columnExt.getModelIndex() == TokenGenMessagesTableModel.RTT_COLUMN_INDEX
                    && TimeDurationStringValue.isTargetClass(
                            model.getColumnClass(TokenGenMessagesTableModel.RTT_COLUMN_INDEX))) {
                columnExt.setCellRenderer(new DefaultTableRenderer(new TimeDurationStringValue()));
            }

            if (columnExt.getModelIndex()
                            == TokenGenMessagesTableModel.RESPONSE_BODY_SIZE_COLUMN_INDEX
                    && SizeBytesStringValue.isTargetClass(
                            model.getColumnClass(
                                    TokenGenMessagesTableModel.RESPONSE_BODY_SIZE_COLUMN_INDEX))) {
                columnExt.setCellRenderer(new DefaultTableRenderer(new SizeBytesStringValue()));
            }
        }
    }

    private class CustomPopupMenu extends JPopupMenu {

        private static final long serialVersionUID = 1L;

        @Override
        public void show(Component invoker, int x, int y) {
            View.getSingleton().getPopupMenu().show(TokenGenMessagesTable.this, x, y);
        }
    }
}
