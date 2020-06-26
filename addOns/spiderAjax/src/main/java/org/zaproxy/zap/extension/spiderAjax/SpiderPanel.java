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
package org.zaproxy.zap.extension.spiderAjax;

import java.awt.BorderLayout;
import java.awt.GridBagConstraints;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.SortedSet;
import java.util.TreeSet;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JLabel;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.control.Control.Mode;
import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.extension.history.HistoryFilter;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.utils.TableExportButton;
import org.zaproxy.zap.view.ScanStatus;
import org.zaproxy.zap.view.table.HistoryReferencesTable;

/**
 * This class creates the Spider AJAX Panel where the found URLs are displayed It has a button to
 * stop the crawler and another one to open the options.
 */
public class SpiderPanel extends AbstractPanel implements SpiderListener {
    private static final long serialVersionUID = 1L;
    private static final Logger logger = Logger.getLogger(SpiderPanel.class);

    private javax.swing.JScrollPane scrollLog = null;
    private javax.swing.JPanel AJAXSpiderPanel = null;
    private javax.swing.JToolBar panelToolbar = null;
    private JLabel filterStatus = null;
    private int foundCount = 0;
    private JLabel foundLabel = new JLabel();
    private ExtensionAjax extension = null;
    private SpiderThread runnable = null;
    private JButton stopScanButton;
    private JButton startScanButton;
    private JButton optionsButton = null;
    private TableExportButton<HistoryReferencesTable> exportButton = null;

    private HistoryReferencesTable spiderResultsTable;
    private AjaxSpiderResultsTableModel spiderResultsTableModel = new AjaxSpiderResultsTableModel();
    private SortedSet<String> visitedUrls = new TreeSet<>();

    private ScanStatus scanStatus = null;

    private JLabel activeScansNameLabel = null;
    private JLabel activeScansValueLabel = null;
    private List<String> activeScans = new ArrayList<>();

    private String targetSite;

    /** This is the default constructor */
    public SpiderPanel(ExtensionAjax e) {
        super();
        this.extension = e;
        this.setLayout(new BorderLayout());
        if (Model.getSingleton().getOptionsParam().getViewParam().getWmUiHandlingOption() == 0) {
            this.setSize(600, 200);
        }
        this.add(getAJAXSpiderPanel(), java.awt.BorderLayout.CENTER);
        scanStatus =
                new ScanStatus(
                        new ImageIcon(
                                SpiderPanel.class.getResource("/resource/icon/16/spiderAjax.png")),
                        this.extension.getMessages().getString("spiderajax.panel.title"));

        this.setDefaultAccelerator(
                this.extension
                        .getView()
                        .getMenuShortcutKeyStroke(KeyEvent.VK_J, KeyEvent.SHIFT_DOWN_MASK, false));
        this.setMnemonic(Constant.messages.getChar("spiderajax.panel.mnemonic"));

        if (View.isInitialised()) {
            View.getSingleton()
                    .getMainFrame()
                    .getMainFooterPanel()
                    .addFooterToolbarRightLabel(scanStatus.getCountLabel());
        }
    }

    /**
     * This method initializes the scrollLog attribute
     *
     * @return javax.swing.JScrollPane
     */
    private javax.swing.JScrollPane getScrollLog() {
        if (scrollLog == null) {
            scrollLog = new javax.swing.JScrollPane();
            scrollLog.setViewportView(getSpiderResultsTable());
            scrollLog.setName("scrollLog");
        }
        return scrollLog;
    }

    /** @return the AJAX Spider Panel */
    private javax.swing.JPanel getAJAXSpiderPanel() {
        if (AJAXSpiderPanel == null) {

            AJAXSpiderPanel = new javax.swing.JPanel();
            AJAXSpiderPanel.setLayout(new java.awt.GridBagLayout());
            AJAXSpiderPanel.setName("Spider AJAX Panel");

            GridBagConstraints gridBagConstraints1 = new GridBagConstraints();
            GridBagConstraints gridBagConstraints2 = new GridBagConstraints();

            gridBagConstraints1.gridx = 0;
            gridBagConstraints1.gridy = 0;
            gridBagConstraints1.weightx = 1.0D;
            gridBagConstraints1.insets = new java.awt.Insets(2, 2, 2, 2);
            gridBagConstraints1.fill = java.awt.GridBagConstraints.HORIZONTAL;
            gridBagConstraints1.anchor = java.awt.GridBagConstraints.NORTHWEST;

            gridBagConstraints2.gridx = 0;
            gridBagConstraints2.gridy = 1;
            gridBagConstraints2.weightx = 1.0;
            gridBagConstraints2.weighty = 1.0;
            gridBagConstraints2.insets = new java.awt.Insets(0, 0, 0, 0);
            gridBagConstraints2.fill = java.awt.GridBagConstraints.BOTH;
            gridBagConstraints2.anchor = java.awt.GridBagConstraints.NORTHWEST;

            AJAXSpiderPanel.add(this.getPanelToolbar(), gridBagConstraints1);
            AJAXSpiderPanel.add(getScrollLog(), gridBagConstraints2);
        }
        return AJAXSpiderPanel;
    }

    /** @return The Stop Scan Button */
    private JButton getStopScanButton() {
        if (stopScanButton == null) {
            stopScanButton = new JButton();
            stopScanButton.setToolTipText(
                    this.extension.getMessages().getString("spiderajax.toolbar.button.stop"));
            stopScanButton.setIcon(
                    new ImageIcon(SpiderPanel.class.getResource("/resource/icon/16/142.png")));
            stopScanButton.setEnabled(false);
            stopScanButton.addActionListener(
                    new ActionListener() {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                            stopScan();
                        }
                    });
        }
        return stopScanButton;
    }

    /**
     * stops a specific thread
     *
     * @param site
     */
    public void stopScan(String site) {
        this.activeScans.remove(site);
        this.setActiveScanLabels();
        this.getStartScanButton().setEnabled(true);
        if (this.activeScans.size() < 1) {
            this.getStopScanButton().setEnabled(false);
        }
        this.runnable.stopSpider();
    }

    /** Stops all threads */
    public void stopScan() {
        resetPanelState();
        if (runnable != null) {
            this.runnable.stopSpider();
        }
    }

    private void resetPanelState() {
        this.activeScans = new ArrayList<>();
        this.setActiveScanLabels();
        this.getStartScanButton().setEnabled(!Mode.safe.equals(Control.getSingleton().getMode()));
        this.getStopScanButton().setEnabled(false);
    }

    /** @return The Start Scan Button */
    private JButton getStartScanButton() {
        if (startScanButton == null) {
            startScanButton = new JButton();
            startScanButton.setText(
                    this.extension.getMessages().getString("spiderajax.toolbar.button.start"));
            startScanButton.setIcon(
                    new ImageIcon(
                            SpiderPanel.class.getResource("/resource/icon/16/spiderAjax.png")));
            startScanButton.setEnabled(!Mode.safe.equals(Control.getSingleton().getMode()));
            startScanButton.addActionListener(
                    new ActionListener() {

                        @Override
                        public void actionPerformed(ActionEvent e) {
                            extension.showScanDialog(null);
                        }
                    });
        }
        return startScanButton;
    }

    /**
     * @param r history reference
     * @param msg the http message
     * @param url the targeted url
     */
    private boolean addHistoryUrl(
            HistoryReference r, HttpMessage msg, String url, ResourceState state) {
        if (isNewUrl(r, msg)) {
            this.spiderResultsTableModel.addHistoryReference(r, state);
            return true;
        }
        return false;
    }

    /**
     * @param r history reference
     * @param msg the http message
     * @return if the url is new or not
     */
    private boolean isNewUrl(HistoryReference r, HttpMessage msg) {
        return !visitedUrls.contains(msg.getRequestHeader().getURI().toString());
    }

    /** @return the Options Button */
    private JButton getOptionsButton() {
        if (optionsButton == null) {
            optionsButton = new JButton();
            optionsButton.setToolTipText(
                    this.extension.getMessages().getString("spiderajax.options.title"));
            optionsButton.setIcon(
                    new ImageIcon(SpiderPanel.class.getResource("/resource/icon/16/041.png")));
            optionsButton.addActionListener(
                    new ActionListener() {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                            Control.getSingleton()
                                    .getMenuToolsControl()
                                    .options(
                                            extension
                                                    .getMessages()
                                                    .getString("spiderajax.options.title"));
                        }
                    });
        }
        return optionsButton;
    }

    private TableExportButton<HistoryReferencesTable> getExportButton() {
        if (exportButton == null) {
            exportButton = new TableExportButton<HistoryReferencesTable>(getSpiderResultsTable());
        }
        return exportButton;
    }
    /** @return the panel toolbar */
    private javax.swing.JToolBar getPanelToolbar() {
        if (panelToolbar == null) {

            panelToolbar = new javax.swing.JToolBar();
            panelToolbar.setLayout(new java.awt.GridBagLayout());
            panelToolbar.setEnabled(true);
            panelToolbar.setFloatable(false);
            panelToolbar.setRollover(true);
            panelToolbar.setPreferredSize(new java.awt.Dimension(800, 30));
            panelToolbar.setFont(new java.awt.Font("Dialog", java.awt.Font.PLAIN, 12));
            panelToolbar.setName("Spider AJAX Toolbar");

            GridBagConstraints gridBagConstraints1 = new GridBagConstraints();
            GridBagConstraints gridBagConstraints2 = new GridBagConstraints();
            GridBagConstraints gridBagConstraints3 = new GridBagConstraints();
            GridBagConstraints gridBagConstraints4 = new GridBagConstraints();
            GridBagConstraints gridBagConstraints5 = new GridBagConstraints();
            GridBagConstraints gridBagConstraintsX = new GridBagConstraints();
            GridBagConstraints gridBagConstraints7 = new GridBagConstraints();
            GridBagConstraints gridBagConstraintsy = new GridBagConstraints();

            gridBagConstraints1.gridx = 0;
            gridBagConstraints1.gridy = 0;
            gridBagConstraints1.insets = new java.awt.Insets(0, 0, 0, 0);
            gridBagConstraints1.anchor = java.awt.GridBagConstraints.WEST;

            gridBagConstraints2.gridx = 1;
            gridBagConstraints2.gridy = 0;
            gridBagConstraints2.insets = new java.awt.Insets(0, 0, 0, 0);
            gridBagConstraints2.anchor = java.awt.GridBagConstraints.WEST;

            gridBagConstraints3.gridx = 2;
            gridBagConstraints3.gridy = 0;
            gridBagConstraints3.insets = new java.awt.Insets(0, 0, 0, 0);
            gridBagConstraints3.anchor = java.awt.GridBagConstraints.WEST;

            gridBagConstraints4.gridx = 3;
            gridBagConstraints4.gridy = 0;
            gridBagConstraints4.insets = new java.awt.Insets(0, 0, 0, 0);
            gridBagConstraints4.anchor = java.awt.GridBagConstraints.WEST;

            gridBagConstraints5.gridx = 4;
            gridBagConstraints5.gridy = 0;
            gridBagConstraints5.insets = new java.awt.Insets(0, 0, 0, 0);
            gridBagConstraints5.anchor = java.awt.GridBagConstraints.WEST;
            gridBagConstraints7.gridx = 6;
            gridBagConstraints7.gridy = 0;
            gridBagConstraints7.insets = new java.awt.Insets(0, 0, 0, 0);
            gridBagConstraints7.anchor = java.awt.GridBagConstraints.WEST;
            gridBagConstraintsX.gridx = 5;
            gridBagConstraintsX.gridy = 0;
            gridBagConstraintsX.weightx = 1.0;
            gridBagConstraintsX.weighty = 1.0;
            gridBagConstraintsX.insets = new java.awt.Insets(0, 0, 0, 0);
            gridBagConstraintsX.anchor = java.awt.GridBagConstraints.EAST;
            gridBagConstraintsX.fill = java.awt.GridBagConstraints.HORIZONTAL;
            gridBagConstraintsy.gridx = 21;
            gridBagConstraintsy.gridy = 0;
            gridBagConstraintsy.insets = new java.awt.Insets(0, 0, 0, 0);
            gridBagConstraintsy.anchor = java.awt.GridBagConstraints.WEST;
            filterStatus =
                    new JLabel(this.extension.getMessages().getString("spiderajax.panel.subtitle"));
            JLabel t1 = new JLabel();

            panelToolbar.add(getStartScanButton(), gridBagConstraints1);
            panelToolbar.add(getStopScanButton(), gridBagConstraints2);
            panelToolbar.add(filterStatus, gridBagConstraints3);
            panelToolbar.add(foundLabel, gridBagConstraints4);
            panelToolbar.add(getExportButton(), gridBagConstraints5);
            panelToolbar.add(t1, gridBagConstraintsX);
            panelToolbar.add(getOptionsButton(), gridBagConstraintsy);
        }
        return panelToolbar;
    }

    private HistoryReferencesTable getSpiderResultsTable() {
        if (spiderResultsTable == null) {
            spiderResultsTable = new AjaxSpiderResultsTable(spiderResultsTableModel);
        }
        return spiderResultsTable;
    }

    /** @param filter the history filter */
    public void setFilterStatus(HistoryFilter filter) {
        filterStatus.setText(filter.toShortString());
        filterStatus.setToolTipText(filter.toLongString());
    }

    /**
     * Starts a new scan with the given name and target.
     *
     * @param displayName the display name of the new scan
     * @param target the target of the scan
     */
    public void startScan(String displayName, AjaxSpiderTarget target) {
        this.startScan(displayName, target, null);
    }

    /**
     * Starts a new scan with the given name and target.
     *
     * @param displayName the display name of the new scan
     * @param target the target of the scan
     * @param listener a listener that will be notified of the scan progress
     */
    public void startScan(String displayName, AjaxSpiderTarget target, SpiderListener listener) {
        if (View.isInitialised()) {
            // Show the tab in case its been closed
            this.setTabFocus();
            this.foundCount = 0;
            this.foundLabel.setText(Integer.toString(this.foundCount));
        }
        this.runnable = extension.createSpiderThread(displayName, target, this);
        this.getStartScanButton().setEnabled(false);
        this.getStopScanButton().setEnabled(true);
        this.activeScans.add(displayName);
        this.setActiveScanLabels();
        spiderResultsTableModel.clear();
        visitedUrls.clear();
        this.targetSite = displayName;
        if (listener != null) {
            this.runnable.addSpiderListener(listener);
        }
        try {
            new Thread(runnable, "ZAP-AjaxSpider").start();
        } catch (Exception e) {
            logger.error(e);
        }
    }

    /** @return the active scans name label */
    private JLabel getActiveScansNameLabel() {
        if (activeScansNameLabel == null) {
            activeScansNameLabel = new javax.swing.JLabel();
            activeScansNameLabel.setText(
                    Constant.messages.getString("spiderajax.panel.toolbar.currentscans.label"));
        }
        return activeScansNameLabel;
    }

    /** @return he number of active scans */
    private JLabel getActiveScansValueLabel() {
        if (activeScansValueLabel == null) {
            activeScansValueLabel = new javax.swing.JLabel();
            activeScansValueLabel.setText("" + activeScans.size());
        }
        return activeScansValueLabel;
    }

    /** sets the number of active scans */
    private void setActiveScanLabels() {
        getActiveScansValueLabel().setText("" + activeScans.size());
        StringBuilder sb = new StringBuilder();
        Iterator<String> iter = activeScans.iterator();
        sb.append("<html>");
        while (iter.hasNext()) {
            sb.append(iter.next());
            sb.append("<br>");
        }
        sb.append("</html>");

        final String toolTip = sb.toString();

        getActiveScansNameLabel().setToolTipText(toolTip);
        getActiveScansValueLabel().setToolTipText(toolTip);

        scanStatus.setScanCount(activeScans.size());
    }

    ScanStatus getScanStatus() {
        return scanStatus;
    }

    public void reset() {
        stopScan();
        spiderResultsTableModel.clear();
        visitedUrls.clear();

        if (View.isInitialised()) {
            this.foundCount = 0;
            this.foundLabel.setText(Integer.toString(this.foundCount));
        }
    }

    void unload() {
        spiderResultsTableModel.unload();
    }

    public void sessionModeChanged(Mode mode) {
        switch (mode) {
            case standard:
            case protect:
            case attack:
                this.getStartScanButton().setEnabled(!extension.isSpiderRunning());
                break;
            case safe:
                stopScan();
        }
    }

    @Override
    public void spiderStarted() {}

    @Override
    public void foundMessage(
            HistoryReference historyReference, HttpMessage httpMessage, ResourceState state) {
        boolean added = addHistoryUrl(historyReference, httpMessage, targetSite, state);
        if (View.isInitialised() && added) {
            foundCount++;
            this.foundLabel.setText(Integer.toString(this.foundCount));
        }
    }

    @Override
    public void spiderStopped() {
        resetPanelState();
    }
}
