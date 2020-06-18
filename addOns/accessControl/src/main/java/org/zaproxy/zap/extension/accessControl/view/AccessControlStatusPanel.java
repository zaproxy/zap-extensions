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
package org.zaproxy.zap.extension.accessControl.view;

import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.util.HashMap;
import java.util.Map;
import javax.swing.Icon;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JScrollPane;
import javax.swing.JToolBar;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.filechooser.FileFilter;
import javax.xml.parsers.ParserConfigurationException;
import org.apache.log4j.Logger;
import org.jdesktop.swingx.JXTable;
import org.jdesktop.swingx.decorator.AbstractHighlighter;
import org.jdesktop.swingx.decorator.ComponentAdapter;
import org.jdesktop.swingx.renderer.DefaultTableRenderer;
import org.jdesktop.swingx.renderer.IconAware;
import org.jdesktop.swingx.renderer.IconValues;
import org.jdesktop.swingx.renderer.MappedValue;
import org.jdesktop.swingx.renderer.StringValues;
import org.jdesktop.swingx.table.TableColumnExt;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.accessControl.AccessControlScannerThread;
import org.zaproxy.zap.extension.accessControl.AccessControlScannerThread.AccessControlNodeResult;
import org.zaproxy.zap.extension.accessControl.AccessControlScannerThread.AccessControlResultEntry;
import org.zaproxy.zap.extension.accessControl.AccessControlScannerThread.AccessControlScanListener;
import org.zaproxy.zap.extension.accessControl.ExtensionAccessControl;
import org.zaproxy.zap.extension.accessControl.view.AccessControlResultsTableModel.AccessControlResultsTableEntry;
import org.zaproxy.zap.extension.httpsessions.HttpSessionsPanel;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.scan.BaseScannerThreadManager;
import org.zaproxy.zap.utils.DesktopUtils;
import org.zaproxy.zap.view.LayoutHelper;
import org.zaproxy.zap.view.panels.AbstractScanToolbarStatusPanel;
import org.zaproxy.zap.view.widgets.WritableFileChooser;

/**
 * The status panel used for the Access Control extension. It allows ZAP users to control and
 * configure the scans, generate a report and see the scan results.
 */
public class AccessControlStatusPanel extends AbstractScanToolbarStatusPanel
        implements AccessControlScanListener {

    private static final long serialVersionUID = 3717381205061196129L;

    private static final String PANEL_NAME = "AccessControlStatusPanel";
    private static final Logger log = Logger.getLogger(AccessControlStatusPanel.class);
    private static final AccessControlResultsTableModel EMPTY_RESULTS_MODEL =
            new AccessControlResultsTableModel();

    private JXTable resultsTable;
    private JScrollPane workPane;
    private JButton reportButton;

    private Map<Integer, AccessControlResultsTableModel> resultsModels;
    private AccessControlResultsTableModel currentResultsModel;
    private ExtensionAccessControl extension;

    public AccessControlStatusPanel(
            ExtensionAccessControl extension,
            BaseScannerThreadManager<AccessControlScannerThread> threadManager) {

        super(
                "accessControl",
                new ImageIcon(
                        AccessControlStatusPanel.class.getResource(
                                "/org/zaproxy/zap/extension/accessControl/resources/icon.png")),
                threadManager);
        this.extension = extension;
        this.resultsModels = new HashMap<>();
        this.currentResultsModel = EMPTY_RESULTS_MODEL;
    }

    @Override
    public void unload() {
        super.unload();
        reset();
    }

    @Override
    public void scanResultObtained(int contextId, AccessControlResultEntry result) {
        getResultsModel(contextId).addEntry(new AccessControlResultsTableEntry(result));
    }

    @Override
    protected Component getWorkPanel() {
        if (workPane == null) {
            workPane = new JScrollPane();
            workPane.setName("AccessControlResultsPane");
            workPane.setViewportView(getScanResultsTable());
            workPane.setFont(new java.awt.Font("Dialog", java.awt.Font.PLAIN, 11));
        }
        return workPane;
    }

    /**
     * Gets the scan results table.
     *
     * @return the scan results table
     */
    private JXTable getScanResultsTable() {
        if (resultsTable == null) {
            // Create the table with a default, empty TableModel and the proper settings
            resultsTable = new JXTable(EMPTY_RESULTS_MODEL);
            resultsTable.setColumnSelectionAllowed(false);
            resultsTable.setCellSelectionEnabled(false);
            resultsTable.setRowSelectionAllowed(true);
            resultsTable.setAutoCreateRowSorter(true);
            resultsTable.setColumnControlVisible(true);
            resultsTable.setAutoCreateColumnsFromModel(false);

            this.setScanResultsTableColumnSizes();

            resultsTable.setName(PANEL_NAME);
            resultsTable.setFont(new java.awt.Font("Dialog", java.awt.Font.PLAIN, 11));
            resultsTable.setDoubleBuffered(true);
            resultsTable.setSelectionMode(
                    javax.swing.ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
            resultsTable
                    .getSelectionModel()
                    .addListSelectionListener(new DisplayMessageOnSelectionValueChange());

            int columnIdx = AccessControlResultsTableModel.COLUMN_INDEX_RESULT;
            TableColumnExt column = resultsTable.getColumnExt(columnIdx);
            column.setCellRenderer(
                    new DefaultTableRenderer(
                            new MappedValue(StringValues.EMPTY, IconValues.NONE), JLabel.CENTER));
            column.setHighlighters(new AccessControlNodeResultIconHighlighter(columnIdx));
        }
        return resultsTable;
    }

    protected AccessControlResultsTableModel getResultsModel(int contextId) {
        AccessControlResultsTableModel model = resultsModels.get(contextId);
        if (model == null) {
            model = new AccessControlResultsTableModel();
            resultsModels.put(contextId, model);
        }
        return model;
    }

    protected void displayMessageInHttpPanel(final HttpMessage msg) {
        View.getSingleton().displayMessage(msg);
    }

    @Override
    protected void switchViewForContext(Context context) {
        if (context == null) {
            this.currentResultsModel = EMPTY_RESULTS_MODEL;
            this.getScanResultsTable().setModel(this.currentResultsModel);
            return;
        }

        this.currentResultsModel = getResultsModel(context.getId());
        this.getScanResultsTable().setModel(this.currentResultsModel);
        this.setScanResultsTableColumnSizes();
    }

    public void reset() {
        this.resultsModels = new HashMap<>();
        this.currentResultsModel = EMPTY_RESULTS_MODEL;
        this.getScanResultsTable().setModel(this.currentResultsModel);
    }

    /** Sets the results table column sizes. */
    private void setScanResultsTableColumnSizes() {
        resultsTable.getColumnModel().getColumn(0).setMinWidth(40);
        resultsTable.getColumnModel().getColumn(0).setPreferredWidth(50); // id

        resultsTable.getColumnModel().getColumn(1).setMinWidth(40);
        resultsTable.getColumnModel().getColumn(1).setPreferredWidth(50); // method

        resultsTable.getColumnModel().getColumn(2).setMinWidth(240);
        resultsTable.getColumnModel().getColumn(2).setPreferredWidth(800); // url

        resultsTable.getColumnModel().getColumn(3).setMinWidth(40);
        resultsTable.getColumnModel().getColumn(3).setPreferredWidth(50); // code

        resultsTable.getColumnModel().getColumn(4).setMinWidth(70);
        resultsTable.getColumnModel().getColumn(4).setPreferredWidth(100); // user

        resultsTable.getColumnModel().getColumn(5).setMinWidth(40);
        resultsTable.getColumnModel().getColumn(5).setPreferredWidth(50); // authorized

        resultsTable.getColumnModel().getColumn(6).setMinWidth(60);
        resultsTable.getColumnModel().getColumn(6).setPreferredWidth(100); // access rule

        resultsTable.getColumnModel().getColumn(7).setMinWidth(40);
        resultsTable.getColumnModel().getColumn(7).setPreferredWidth(50); // result
    }

    @Override
    public void scanStarted(int contextId) {
        super.scanStarted(contextId);
        getResultsModel(contextId).clear();
    }

    @Override
    protected int addToolBarElements(JToolBar toolbar, short location, int gridX) {
        if (location == TOOLBAR_LOCATION_AFTER_PROGRESS_BAR) {
            reportButton = new JButton();
            reportButton.setText(
                    Constant.messages.getString("accessControl.toolbar.button.report"));
            reportButton.setIcon(
                    new ImageIcon(
                            HttpSessionsPanel.class.getResource("/resource/icon/16/177.png")));
            reportButton.setEnabled(false);

            // Add the proper behavior for the generate report button: allow users to select a
            // report location, generate the report and open it in the browser
            reportButton.addActionListener(
                    new ActionListener() {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                            File targetFile = selectReportLocation();
                            if (targetFile == null) {
                                return;
                            }

                            File generatedFile = null;
                            try {
                                generatedFile =
                                        extension.generateAccessControlReport(
                                                getSelectedContext().getId(), targetFile);
                            } catch (ParserConfigurationException e1) {
                                log.error("Failed to generate access control report:", e1);
                            }
                            // Check if the generation was OK
                            if (generatedFile == null) {
                                View.getSingleton()
                                        .showMessageDialog(
                                                Constant.messages.getString(
                                                        "report.unknown.error",
                                                        targetFile.getName()));
                                return;
                            }

                            // Try to show the report in the default browser
                            DesktopUtils.openUrlInBrowser(generatedFile.toURI());
                        }
                    });
            toolbar.add(reportButton, LayoutHelper.getGBC(gridX++, 0, 1, 0));
        }
        return gridX;
    }

    /**
     * Show a File Chooser dialog allowing users to select the location where to save the generated
     * report.
     *
     * @return the file in which to save, or <code>null</code>, if the user cancelled the process
     */
    private File selectReportLocation() {
        // create a file chooser that requires writable files and starts in the user directory
        JFileChooser chooser =
                new WritableFileChooser(Model.getSingleton().getOptionsParam().getUserDirectory());

        chooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
        chooser.setAcceptAllFileFilterUsed(false);
        chooser.setFileFilter(
                new FileFilter() {
                    @Override
                    public boolean accept(File file) {
                        String lcFileName = file.getName().toLowerCase();
                        return (lcFileName.endsWith(".htm") || lcFileName.endsWith(".html"));
                    }

                    @Override
                    public String getDescription() {
                        return Constant.messages.getString("file.format.html");
                    }
                });

        File file = null;
        // Default the filename to a reasonable extension
        chooser.setSelectedFile(new File("ZAP Access Control Report.html"));

        int rc = chooser.showSaveDialog(View.getSingleton().getMainFrame());
        if (rc == JFileChooser.APPROVE_OPTION) {
            file = chooser.getSelectedFile();
            return file;
        }
        return null;
    }

    @Override
    protected void contextSelected(Context context) {
        // Just enable the reportButton if something's selected
        if (context != null) {
            reportButton.setEnabled(true);
        } else {
            reportButton.setEnabled(false);
        }
        super.contextSelected(context);
    }

    @Override
    protected void startScan(Context context) {
        log.debug("Access Control start on Context: " + context);
        extension.showScanOptionsDialog(context);
    }

    @Override
    protected boolean hasOptions() {
        // We don't have options for the Access Control extension so remove them.
        return false;
    }

    public HistoryReference getSelectedHistoryReference() {
        final int selectedRow = resultsTable.getSelectedRow();
        if (selectedRow != -1 && currentResultsModel != null) {
            return currentResultsModel
                    .getEntry(resultsTable.convertRowIndexToModel(selectedRow))
                    .getHistoryReference();
        }
        return null;
    }

    /**
     * Utility class used to display the currently selected message in the HttpRequest/Response
     * panels.
     */
    protected class DisplayMessageOnSelectionValueChange implements ListSelectionListener {

        @Override
        public void valueChanged(final ListSelectionEvent evt) {
            if (!evt.getValueIsAdjusting()) {
                HistoryReference hRef = getSelectedHistoryReference();
                if (hRef != null) {
                    try {
                        displayMessageInHttpPanel(hRef.getHttpMessage());
                    } catch (HttpMalformedHeaderException | DatabaseException e) {
                        log.error(e.getMessage(), e);
                    }
                }
            }
        }
    }

    /**
     * A {@link org.jdesktop.swingx.decorator.Highlighter Highlighter} for a column that indicates,
     * using icons and tool tip, the result of the access control of a node.
     *
     * <p>The expected type/class of the cell values is {@link AccessControlNodeResult}.
     */
    private static class AccessControlNodeResultIconHighlighter extends AbstractHighlighter {

        private static final ImageIcon RESULT_UNKNOWN_ICON;
        private static final ImageIcon RESULT_VALID_ICON;
        private static final ImageIcon RESULT_ILLEGAL_ICON;

        static {
            RESULT_UNKNOWN_ICON =
                    new ImageIcon(
                            AccessControlStatusPanel.class.getResource(
                                    "/resource/icon/20/info.png"));
            RESULT_VALID_ICON =
                    new ImageIcon(
                            AccessControlStatusPanel.class.getResource(
                                    "/resource/icon/20/valid.png"));
            RESULT_ILLEGAL_ICON =
                    new ImageIcon(
                            AccessControlStatusPanel.class.getResource(
                                    "/resource/icon/20/error.png"));
        }

        private final int columnIndex;

        public AccessControlNodeResultIconHighlighter(final int columnIndex) {
            this.columnIndex = columnIndex;
        }

        @Override
        protected Component doHighlight(Component component, ComponentAdapter adapter) {
            AccessControlNodeResult cell = (AccessControlNodeResult) adapter.getValue(columnIndex);

            Icon icon = getIcon(cell);
            if (component instanceof IconAware) {
                ((IconAware) component).setIcon(icon);
            } else if (component instanceof JLabel) {
                ((JLabel) component).setIcon(icon);
            }

            if (component instanceof JLabel) {
                ((JLabel) component).setToolTipText(cell.toString());
            }

            return component;
        }

        private static Icon getIcon(AccessControlNodeResult result) {
            switch (result) {
                case ILLEGAL:
                    return RESULT_ILLEGAL_ICON;
                case VALID:
                    return RESULT_VALID_ICON;
                case UNKNOWN:
                    return RESULT_UNKNOWN_ICON;
            }
            return null;
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
