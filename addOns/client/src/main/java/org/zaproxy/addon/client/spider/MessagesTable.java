/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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
package org.zaproxy.addon.client.spider;

import java.awt.Component;
import javax.swing.Icon;
import javax.swing.ImageIcon;
import javax.swing.JLabel;
import javax.swing.SortOrder;
import javax.swing.table.TableModel;
import org.jdesktop.swingx.decorator.AbstractHighlighter;
import org.jdesktop.swingx.decorator.ComponentAdapter;
import org.jdesktop.swingx.renderer.DefaultTableRenderer;
import org.jdesktop.swingx.renderer.IconAware;
import org.jdesktop.swingx.renderer.IconValues;
import org.jdesktop.swingx.renderer.MappedValue;
import org.jdesktop.swingx.renderer.StringValues;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.zaproxy.addon.client.spider.ClientSpider.ResourceState;
import org.zaproxy.addon.client.spider.MessagesTableModel.ProcessedCellItem;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.table.HistoryReferencesTable;

@SuppressWarnings("serial")
public class MessagesTable extends HistoryReferencesTable {

    private static final long serialVersionUID = 1L;

    private static final String RESULTS_TABLE_NAME = "ClientSpiderMessagesTable";

    private final ExtensionHistory extensionHistory;

    public MessagesTable(MessagesTableModel model) {
        super(model);

        setName(RESULTS_TABLE_NAME);

        setAutoCreateColumnsFromModel(false);

        getColumnExt(0)
                .setCellRenderer(
                        new DefaultTableRenderer(
                                new MappedValue(StringValues.EMPTY, IconValues.NONE),
                                JLabel.CENTER));
        getColumnExt(0).setHighlighters(new ProcessedCellItemIconHighlighter(0));

        getColumnExt(Constant.messages.getString("view.href.table.header.timestamp.response"))
                .setVisible(false);
        getColumnExt(Constant.messages.getString("view.href.table.header.size.requestheader"))
                .setVisible(false);
        getColumnExt(Constant.messages.getString("view.href.table.header.size.requestbody"))
                .setVisible(false);

        extensionHistory =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionHistory.class);
    }

    @Override
    public void setModel(TableModel dataModel) {
        // Keep the same column sorted when model is changed
        int sortedcolumnIndex = getSortedColumnIndex();
        SortOrder sortOrder = getSortOrder(sortedcolumnIndex);
        super.setModel(dataModel);
        if (sortedcolumnIndex != -1) {
            setSortOrder(sortedcolumnIndex, sortOrder);
        }
    }

    @Override
    protected HistoryReference getHistoryReferenceAtViewRow(int row) {
        HistoryReference historyReference = super.getHistoryReferenceAtViewRow(row);
        if (historyReference == null) {
            return null;
        }

        if (extensionHistory == null
                || extensionHistory.getHistoryReference(historyReference.getHistoryId()) == null) {
            // Associated message was deleted in the meantime.
            return null;
        }

        return historyReference;
    }

    private static class ProcessedCellItemIconHighlighter extends AbstractHighlighter {

        private static final ImageIcon ALLOWED_ICON =
                DisplayUtils.getScaledIcon(
                        MessagesTable.class.getResource("/resource/icon/16/152.png"));

        private static final ImageIcon NOT_ALLOWED_ICON =
                DisplayUtils.getScaledIcon(
                        MessagesTable.class.getResource("/resource/icon/16/149.png"));

        private final int columnIndex;

        public ProcessedCellItemIconHighlighter(final int columnIndex) {
            this.columnIndex = columnIndex;
        }

        @Override
        protected Component doHighlight(Component component, ComponentAdapter adapter) {
            ProcessedCellItem cell = (ProcessedCellItem) adapter.getValue(columnIndex);

            boolean allowed = cell.getState() == ResourceState.ALLOWED;
            Icon icon = getIcon(allowed);
            if (component instanceof IconAware) {
                ((IconAware) component).setIcon(icon);
            } else if (component instanceof JLabel) {
                ((JLabel) component).setIcon(icon);
            }

            if (component instanceof JLabel) {
                ((JLabel) component).setText(allowed ? "" : cell.getLabel());
            }

            return component;
        }

        private static Icon getIcon(boolean allowed) {
            return allowed ? ALLOWED_ICON : NOT_ALLOWED_ICON;
        }

        // Method/JavaDoc copied from
        // org.jdesktop.swingx.decorator.IconHighlighter#canHighlight(Component, ComponentAdapter)
        @Override
        protected boolean canHighlight(final Component component, final ComponentAdapter adapter) {
            return component instanceof IconAware || component instanceof JLabel;
        }
    }
}
