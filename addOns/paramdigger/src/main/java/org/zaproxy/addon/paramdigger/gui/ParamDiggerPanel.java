/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.addon.paramdigger.gui;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.EventQueue;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.paramdigger.ExtensionParamDigger;
import org.zaproxy.addon.paramdigger.GuesserProgressListener;
import org.zaproxy.addon.paramdigger.GuesserScan;
import org.zaproxy.addon.paramdigger.ParamDiggerOptions;
import org.zaproxy.addon.paramdigger.ParamDiggerResultEventListener;
import org.zaproxy.addon.paramdigger.ParamGuessResultEvent;
import org.zaproxy.addon.paramdigger.ParamGuesserScanController;
import org.zaproxy.zap.view.ScanPanel2;

@SuppressWarnings("serial")
public class ParamDiggerPanel extends ScanPanel2<GuesserScan, ParamGuesserScanController> {

    private static final long serialVersionUID = 1L;

    private final ParamDiggerOptions options;

    private JTabbedPane tabbedPane;
    private JTextArea outputArea;
    private ParamDiggerHistoryTableModel emptyTableModel;
    private JTable historyTable;

    private JButton startScanButton;

    private JPanel mainPanel;

    private ProgressListener progressListener;
    private ResultListener resultListener;
    private GuesserScan previousScan;

    public ParamDiggerPanel(
            ParamGuesserScanController scanController,
            ParamDiggerOptions options,
            Runnable scanStartRunnable) {
        super("paramdigger", ExtensionParamDigger.getIcon(), scanController);

        getNewScanButton().setText(Constant.messages.getString("paramdigger.toolbar.button.new"));
        getNewScanButton().setIcon(getIcon());
        getNewScanButton().addActionListener(e -> scanStartRunnable.run());

        this.options = options;
    }

    @Override
    protected Component getWorkPanel() {
        if (mainPanel == null) {
            mainPanel = new JPanel(new BorderLayout());

            emptyTableModel = new ParamDiggerHistoryTableModel();
            historyTable = new ParamDiggerResultsTable(emptyTableModel);
            outputArea = new JTextArea();
            outputArea.setEditable(false);

            tabbedPane = new JTabbedPane();
            tabbedPane.addTab(
                    Constant.messages.getString("paramdigger.panel.tab.history"),
                    new JScrollPane(historyTable));
            tabbedPane.addTab(
                    Constant.messages.getString("paramdigger.panel.tab.output"),
                    new JScrollPane(outputArea));
            mainPanel.add(tabbedPane);
        }
        return mainPanel;
    }

    @Override
    public void scannerStarted(GuesserScan scan) {
        super.scannerStarted(scan);
        scan.addProgressListener(getProgressListener());
    }

    @Override
    protected void switchView(GuesserScan scan) {
        if (previousScan != null) {
            previousScan.getOutputModel().removeResultListener(getResultListener());
        }
        previousScan = scan;
        if (scan != null) {
            historyTable.setModel(scan.getTableModel());
            outputArea.setText(scan.getOutputModel().getOutput());
            scan.getOutputModel().addResultListener(getResultListener());
        } else {
            historyTable.setModel(emptyTableModel);
            outputArea.setText("");
        }
        mainPanel.revalidate();
        mainPanel.repaint();
    }

    @Override
    protected JButton getNewScanButton() {
        if (startScanButton == null) {
            startScanButton = new JButton();
        }
        return startScanButton;
    }

    @Override
    protected int getNumberOfScansToShow() {
        return options.getMaxFinishedScansInUi();
    }

    @Override
    public void clearFinishedScans() {
        if (options.isPromptToClearFinishedScans()) {
            JCheckBox dontPromptCheckBox =
                    new JCheckBox(
                            Constant.messages.getString(
                                    "paramdigger.toolbar.confirm.clear.dontPrompt"));
            Object[] messages = {
                Constant.messages.getString("paramdigger.toolbar.confirm.clear"),
                "\n",
                dontPromptCheckBox
            };
            int option =
                    JOptionPane.showConfirmDialog(
                            View.getSingleton().getMainFrame(),
                            messages,
                            Constant.messages.getString("paramdigger.panel.title"),
                            JOptionPane.YES_NO_OPTION);
            if (dontPromptCheckBox.isSelected()) {
                options.setPromptToClearFinishedScans(false);
            }

            if (option != JOptionPane.YES_OPTION) {
                return;
            }
        }
        super.clearFinishedScans();
    }

    private ProgressListener getProgressListener() {
        if (progressListener == null) {
            progressListener = new ProgressListener();
        }
        return progressListener;
    }

    private ParamDiggerResultEventListener getResultListener() {
        if (resultListener == null) {
            resultListener = new ResultListener();
        }
        return resultListener;
    }

    @Override
    public void unload() {
        super.unload();
    }

    @Override
    public boolean hasOptionsButton() {
        return false;
    }

    private class ResultListener implements ParamDiggerResultEventListener {

        @Override
        public void notifyResult(ParamGuessResultEvent event) {
            EventQueue.invokeLater(() -> outputArea.append(event.getResult().toString()));
        }
    }

    private class ProgressListener implements GuesserProgressListener {

        @Override
        public void updateProgress(int id, String displayName, int paramsTried, int totalParams) {
            EventQueue.invokeLater(() -> scanProgress(id, displayName, paramsTried, totalParams));
        }

        @Override
        public void completed(int id, String displayName, boolean successfully) {
            EventQueue.invokeLater(() -> scanFinshed(id, displayName));
        }
    }
}
