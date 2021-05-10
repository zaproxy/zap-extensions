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
package org.zaproxy.zap.extension.sse.ui;

import java.awt.EventQueue;
import java.awt.Font;
import java.awt.Rectangle;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.util.ArrayList;
import java.util.List;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.TableColumn;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jdesktop.swingx.JXTable;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.httppanel.HttpPanel;
import org.zaproxy.zap.extension.sse.EventStreamException;
import org.zaproxy.zap.extension.sse.ServerSentEvent;
import org.zaproxy.zap.utils.TableColumnManager;

/** Wraps a {@link JXTable} that is used to display Server-Sent Events. */
public class EventStreamView implements Runnable {

    public static final String PANEL_NAME = "sse.table";

    private static final Logger logger = LogManager.getLogger(EventStreamView.class);

    protected JXTable view;
    protected EventStreamViewModel model;

    private HttpPanel requestPanel;
    private HttpPanel responsePanel;
    private List<ServerSentEvent> displayQueue;

    private Thread thread = null;

    public EventStreamView(EventStreamViewModel model) {
        this.model = model;

        displayQueue = new ArrayList<>();
    }

    /**
     * Lazy initializes the view component.
     *
     * @return events view
     */
    public JXTable getViewComponent() {
        if (view == null) {
            view = new JXTable();
            view.setName(getViewComponentName());
            view.setModel(model);
            view.setColumnSelectionAllowed(false);
            view.setCellSelectionEnabled(false);
            view.setRowSelectionAllowed(true);
            view.setAutoCreateRowSorter(false);
            view.setColumnControlVisible(true);

            // prevents columns to loose their width when switching models
            view.setAutoCreateColumnsFromModel(false);

            setColumnWidths();

            view.setFont(new Font("Dialog", Font.PLAIN, 12));
            view.setDoubleBuffered(true);
            view.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
            view.addMouseListener(getMouseListener());

            view.getSelectionModel().addListSelectionListener(getListSelectionListener());

            view.revalidate();

            // standalone - allows to hide/show columns
            new TableColumnManager(view);
        }
        return view;
    }

    protected String getViewComponentName() {
        return PANEL_NAME;
    }

    protected MouseListener getMouseListener() {
        return new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {

                if (SwingUtilities.isRightMouseButton(e)) {

                    // Select table item
                    int row = view.rowAtPoint(e.getPoint());
                    if (row < 0 || !view.getSelectionModel().isSelectedIndex(row)) {
                        view.getSelectionModel().clearSelection();
                        if (row >= 0) {
                            view.getSelectionModel().setSelectionInterval(row, row);
                        }
                    }

                    View.getSingleton().getPopupMenu().show(e.getComponent(), e.getX(), e.getY());
                }
            }
        };
    }

    protected ListSelectionListener getListSelectionListener() {
        return e -> {
            // only display events when there are no more selection changes.
            if (!e.getValueIsAdjusting()) {
                int rowIndex = view.getSelectedRow();
                if (rowIndex < 0) {
                    // selection got filtered away
                    return;
                }

                EventStreamViewModel model = (EventStreamViewModel) view.getModel();

                // as we use a JTable here, that can be sorted, we have to
                // transform the row index to the appropriate model row
                int modelRow = view.convertRowIndexToModel(rowIndex);
                final ServerSentEvent event = model.getServerSentEvent(modelRow);
                readAndDisplay(event);
            }
        };
    }

    protected void setColumnWidths() {
        // channel + consecutive number
        setColumnWidth(0, 50, 70);

        // timestamp
        setColumnWidth(1, 140, 140);

        // last event id
        setColumnWidth(2, 95, 95);

        // event type
        setColumnWidth(3, 80, 90);

        // data (do not set max & preferred size => stretches to maximum)
        setColumnWidth(4, 100, -1);
    }

    /**
     * Helper method for setting the column widths of this view.
     *
     * @param index
     * @param min
     * @param preferred
     */
    protected void setColumnWidth(int index, int min, int preferred) {
        TableColumn column = view.getColumnModel().getColumn(index);

        if (min != -1) {
            column.setMinWidth(min);
        }

        if (preferred != -1) {
            column.setPreferredWidth(preferred);
        }
    }

    @Override
    public void run() {
        ServerSentEvent event = null;
        int count = 0;

        do {
            synchronized (displayQueue) {
                count = displayQueue.size();
                if (count == 0) {
                    break;
                }

                event = displayQueue.get(0);
                displayQueue.remove(0);
            }

            try {
                final ServerSentEvent eventToDisplay = event;
                EventQueue.invokeAndWait(
                        () -> {
                            requestPanel.clearView(true);
                            responsePanel.setMessage(eventToDisplay, true);
                            responsePanel.setTabFocus();
                        });

            } catch (Exception e) {
                // ZAP: Added logging.
                logger.error(e.getMessage(), e);
            }

            // wait some time to allow another selection event to be triggered
            try {
                Thread.sleep(200);
            } catch (Exception e) {
                // safely ignore exception
            }
        } while (true);
    }

    public void setDisplayPanel(HttpPanel requestPanel, HttpPanel responsePanel) {
        this.requestPanel = requestPanel;
        this.responsePanel = responsePanel;
    }

    private void readAndDisplay(final ServerSentEvent event) {
        if (event == null) {
            return;
        }

        synchronized (displayQueue) {
            if (displayQueue.size() > 0) {
                displayQueue.clear();
            }

            // TODO: Should I really do this?
            //            event.tempUserObj =
            // EventStreamPanel.connectedChannelIds.contains(event.channel.id);
            displayQueue.add(event);
        }

        if (thread != null && thread.isAlive()) {
            return;
        }

        thread = new Thread(this);
        thread.setPriority(Thread.NORM_PRIORITY);
        thread.start();
    }

    public void revalidate() {
        view.revalidate();
    }

    public void selectAndShowItem(ServerSentEvent event) throws EventStreamException {
        Integer modelRowIndex = model.getModelRowIndexOf(event);

        if (modelRowIndex == null) {
            throw new EventStreamException("Element not found");
        }

        int viewRowIndex = view.convertRowIndexToView(modelRowIndex);
        view.setRowSelectionInterval(viewRowIndex, viewRowIndex);

        int rowHeight = view.getRowHeight();
        Rectangle r = new Rectangle(0, rowHeight * viewRowIndex, 10, rowHeight);
        view.scrollRectToVisible(r);
    }

    public void pause() {
        getViewComponent().setEnabled(false);
    }

    public void resume() {
        getViewComponent().setEnabled(true);
        getViewComponent().revalidate();
    }
}
