/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2017 The ZAP Development Team
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
package org.zaproxy.zap.extension.spiderAjax;

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
import org.zaproxy.zap.extension.spiderAjax.AjaxSpiderResultsTableModel.ProcessedCellItem;
import org.zaproxy.zap.extension.spiderAjax.SpiderListener.ResourceState;
import org.zaproxy.zap.view.table.HistoryReferencesTable;

@SuppressWarnings("serial")
public class AjaxSpiderResultsTable extends HistoryReferencesTable {

    private static final long serialVersionUID = 1L;

    private static final String RESULTS_TABLE_NAME = "AjaxSpiderResultsTable";

    private final ExtensionHistory extensionHistory;

    public AjaxSpiderResultsTable(AjaxSpiderResultsTableModel resultsModel) {
        super(resultsModel);

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

    /**
     * A {@link org.jdesktop.swingx.decorator.Highlighter Highlighter} for a column that indicates,
     * using icons and text, whether or not an entry was processed, that is, is or not in scope.
     *
     * <p>The expected type/class of the cell values is {@code ProcessedCellItem}.
     */
    private static class ProcessedCellItemIconHighlighter extends AbstractHighlighter {

        /** The icon that indicates the entry was processed. */
        private static final ImageIcon PROCESSED_ICON =
                new ImageIcon(
                        AjaxSpiderResultsTable.class.getResource("/resource/icon/16/152.png"));

        /** The icon that indicates the entry was not processed. */
        private static final ImageIcon NOT_PROCESSED_ICON =
                new ImageIcon(
                        AjaxSpiderResultsTable.class.getResource("/resource/icon/16/149.png"));

        private final int columnIndex;

        public ProcessedCellItemIconHighlighter(final int columnIndex) {
            this.columnIndex = columnIndex;
        }

        @Override
        protected Component doHighlight(Component component, ComponentAdapter adapter) {
            ProcessedCellItem cell = (ProcessedCellItem) adapter.getValue(columnIndex);

            boolean processed = cell.getState() == ResourceState.PROCESSED;
            Icon icon = getProcessedIcon(processed);
            if (component instanceof IconAware) {
                ((IconAware) component).setIcon(icon);
            } else if (component instanceof JLabel) {
                ((JLabel) component).setIcon(icon);
            }

            if (component instanceof JLabel) {
                ((JLabel) component).setText(processed ? "" : cell.getLabel());
            }

            return component;
        }

        private static Icon getProcessedIcon(final boolean processed) {
            return processed ? PROCESSED_ICON : NOT_PROCESSED_ICON;
        }

        /**
         * {@inheritDoc}
         *
         * <p>Overridden to return true if the component is of type IconAware or of type JLabel,
         * false otherwise.
         *
         * <p>Note: special casing JLabel is for backward compatibility - application highlighting
         * code which doesn't use the Swingx renderers would stop working otherwise.
         */
        // Method/JavaDoc copied from
        // org.jdesktop.swingx.decorator.IconHighlighter#canHighlight(Component, ComponentAdapter)
        @Override
        protected boolean canHighlight(final Component component, final ComponentAdapter adapter) {
            return component instanceof IconAware || component instanceof JLabel;
        }
    }
}
