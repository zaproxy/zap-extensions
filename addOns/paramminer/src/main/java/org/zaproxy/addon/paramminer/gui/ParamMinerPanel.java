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
package org.zaproxy.addon.paramminer.gui;

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
import org.zaproxy.addon.paramminer.ExtensionParamMiner;
import org.zaproxy.addon.paramminer.GuesserProgressListener;
import org.zaproxy.addon.paramminer.GuesserScan;
import org.zaproxy.addon.paramminer.ParamGuessResultEvent;
import org.zaproxy.addon.paramminer.ParamGuesserScanController;
import org.zaproxy.addon.paramminer.ParamMinerOptions;
import org.zaproxy.addon.paramminer.ParamMinerResultEventListener;
import org.zaproxy.zap.view.ScanPanel2;

@SuppressWarnings("serial")
public class ParamMinerPanel extends ScanPanel2<GuesserScan, ParamGuesserScanController> {

    private static final long serialVersionUID = 1L;

    private final ParamMinerOptions options;

    private JTabbedPane tabbedPane;
    private JTextArea outputArea;
    private ParamMinerHistoryTableModel emptyTableModel;
    private JTable historyTable;

    private JButton startScanButton;

    private JPanel mainPanel;

    private ProgressListener progressListener;
    private ResultListener resultListener;
    private GuesserScan previousScan;

    public ParamMinerPanel(
            ParamGuesserScanController scanController,
            ParamMinerOptions options,
            Runnable scanStartRunnable) {
        super("paramminer", ExtensionParamMiner.getIcon(), scanController);

        getNewScanButton().setText(Constant.messages.getString("paramminer.toolbar.button.new"));
        getNewScanButton().setIcon(getIcon());
        getNewScanButton().addActionListener(e -> scanStartRunnable.run());

        this.options = options;
    }

    @Override
    protected Component getWorkPanel() {
        if (mainPanel == null) {
            mainPanel = new JPanel(new BorderLayout());

            emptyTableModel = new ParamMinerHistoryTableModel();
            historyTable = new ParamMinerResultsTable(emptyTableModel);
            outputArea = new JTextArea();
            outputArea.setEditable(false);

            tabbedPane = new JTabbedPane();
            tabbedPane.addTab(
                    Constant.messages.getString("paramminer.panel.tab.history"),
                    new JScrollPane(historyTable));
            tabbedPane.addTab(
                    Constant.messages.getString("paramminer.panel.tab.output"),
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
                                    "paramminer.toolbar.confirm.clear.dontPrompt"));
            Object[] messages = {
                Constant.messages.getString("paramminer.toolbar.confirm.clear"),
                "\n",
                dontPromptCheckBox
            };
            int option =
                    JOptionPane.showConfirmDialog(
                            View.getSingleton().getMainFrame(),
                            messages,
                            Constant.messages.getString("paramminer.panel.title"),
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

    private ParamMinerResultEventListener getResultListener() {
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

    private class ResultListener implements ParamMinerResultEventListener {

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
