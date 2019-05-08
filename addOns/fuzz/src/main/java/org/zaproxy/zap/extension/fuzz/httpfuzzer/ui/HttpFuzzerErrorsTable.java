/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2015 The ZAP Development Team
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
package org.zaproxy.zap.extension.fuzz.httpfuzzer.ui;

import java.awt.Container;
import javax.swing.JScrollPane;
import javax.swing.JViewport;
import javax.swing.ListSelectionModel;
import javax.swing.SortOrder;
import javax.swing.SwingUtilities;
import javax.swing.table.TableModel;
import org.jdesktop.swingx.JXTable;
import org.zaproxy.zap.utils.StickyScrollbarAdjustmentListener;

public class HttpFuzzerErrorsTable extends JXTable {

    private static final long serialVersionUID = 8652281391044780396L;

    private boolean autoScroll;
    private StickyScrollbarAdjustmentListener autoScrollScrollbarAdjustmentListener;

    public HttpFuzzerErrorsTable(String name, HttpFuzzerErrorsTableModel errorsModel) {
        super();

        autoScroll = true;

        setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);

        setSortOrderCycle(SortOrder.ASCENDING, SortOrder.DESCENDING, SortOrder.UNSORTED);

        setColumnSelectionAllowed(false);
        setCellSelectionEnabled(false);
        setRowSelectionAllowed(true);
        setColumnControlVisible(true);

        setName(name);

        setAutoCreateColumnsFromModel(false);
        setModel(errorsModel);
        createDefaultColumnsFromModel();

        getColumnExt(0).setPrototypeValue(Long.valueOf(1000));
        getColumnExt(1)
                .setPrototypeValue(
                        "The error message contains a lot of text which occupies a lot more space than the task ID.");

        initializeColumnWidths();

        // Sort on task ID
        setSortOrder(0, SortOrder.ASCENDING);
    }

    /**
     * Sets if the vertical scroll bar of the wrapper {@code JScrollPane} should be automatically
     * scrolled on new values.
     *
     * <p>Default value is to {@code true}.
     *
     * @param autoScroll {@code true} if vertical scroll bar should be automatically scrolled on new
     *     values, {@code false} otherwise.
     */
    public void setAutoScrollOnNewValues(boolean autoScroll) {
        if (this.autoScroll == autoScroll) {
            return;
        }
        if (this.autoScroll) {
            removeAutoScrollScrollbarAdjustmentListener();
        }

        this.autoScroll = autoScroll;

        if (this.autoScroll) {
            addAutoScrollScrollbarAdjustmentListener();
        }
    }

    /**
     * Tells whether or not the vertical scroll bar of the wrapper {@code JScrollPane} is
     * automatically scrolled on new values.
     *
     * @return {@code true} if the vertical scroll bar is automatically scrolled on new values,
     *     {@code false} otherwise.
     * @see #setAutoScrollOnNewValues(boolean)
     */
    public boolean isAutoScrollOnNewValues() {
        return autoScroll;
    }

    private void addAutoScrollScrollbarAdjustmentListener() {
        JScrollPane scrollPane = getEnclosingScrollPane();
        if (scrollPane != null && autoScrollScrollbarAdjustmentListener == null) {
            autoScrollScrollbarAdjustmentListener = new StickyScrollbarAdjustmentListener();
            scrollPane
                    .getVerticalScrollBar()
                    .addAdjustmentListener(autoScrollScrollbarAdjustmentListener);
        }
    }

    private void removeAutoScrollScrollbarAdjustmentListener() {
        JScrollPane scrollPane = getEnclosingScrollPane();
        if (scrollPane != null && autoScrollScrollbarAdjustmentListener != null) {
            scrollPane
                    .getVerticalScrollBar()
                    .removeAdjustmentListener(autoScrollScrollbarAdjustmentListener);
            autoScrollScrollbarAdjustmentListener = null;
        }
    }

    /**
     * {@inheritDoc}
     *
     * <p>Overridden to set auto-scroll on new values, if enabled.
     */
    @Override
    protected void configureEnclosingScrollPane() {
        super.configureEnclosingScrollPane();

        if (isAutoScrollOnNewValues()) {
            addAutoScrollScrollbarAdjustmentListener();
        }
    }

    /**
     * {@inheritDoc}
     *
     * <p>Overridden to unset auto-scroll on new values, if enabled.
     */
    @Override
    protected void unconfigureEnclosingScrollPane() {
        super.unconfigureEnclosingScrollPane();

        if (isAutoScrollOnNewValues()) {
            removeAutoScrollScrollbarAdjustmentListener();
        }
    }

    /**
     * {@inheritDoc}
     *
     * <p>Overridden to take into account for possible parent {@code JLayer}s.
     *
     * @see javax.swing.JLayer
     */
    // Note: Same implementation as in JXTable#getEnclosingScrollPane() but changed to get the
    // parent and viewport view using
    // the methods SwingUtilities#getUnwrappedParent(Component) and
    // SwingUtilities#getUnwrappedView(JViewport) respectively.
    @Override
    protected JScrollPane getEnclosingScrollPane() {
        Container p = SwingUtilities.getUnwrappedParent(this);
        if (p instanceof JViewport) {
            Container gp = p.getParent();
            if (gp instanceof JScrollPane) {
                JScrollPane scrollPane = (JScrollPane) gp;
                // Make certain we are the viewPort's view and not, for
                // example, the rowHeaderView of the scrollPane -
                // an implementor of fixed columns might do this.
                JViewport viewport = scrollPane.getViewport();
                if (viewport == null || SwingUtilities.getUnwrappedView(viewport) != this) {
                    return null;
                }
                return scrollPane;
            }
        }
        return null;
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
}
