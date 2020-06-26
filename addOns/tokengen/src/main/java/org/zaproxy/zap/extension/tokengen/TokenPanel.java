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
package org.zaproxy.zap.extension.tokengen;

import java.awt.CardLayout;
import java.awt.EventQueue;
import java.awt.GridBagConstraints;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.io.File;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.JScrollPane;
import javax.swing.JTextPane;
import javax.swing.JToggleButton;
import javax.swing.JToolBar;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.httppanel.HttpPanel;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.utils.FontUtils;
import org.zaproxy.zap.view.ScanStatus;
import org.zaproxy.zap.view.ZapToggleButton;
import org.zaproxy.zap.view.widgets.WritableFileChooser;

public class TokenPanel extends AbstractPanel {

    private static final long serialVersionUID = 1L;

    /**
     * @deprecated (7) Replaced by {@link #RESULTS_TABLE_NAME}, the results are shown in a table. It
     *     will be removed in a future release.
     */
    @Deprecated public static final String PANEL_NAME = "tokenpanel";

    /** The name of the table that shows the token get messages. */
    public static final String RESULTS_TABLE_NAME = "TokenGenMessagesTable";

    private ExtensionTokenGen extension = null;
    private JPanel panelCommand = null;
    private JToolBar panelToolbar = null;
    private JScrollPane jScrollPane = null;
    private TokenGenMessagesTableModel resultsModel = new TokenGenMessagesTableModel();
    private JTextPane initialMessage = null;

    private JButton stopScanButton = null;
    private ZapToggleButton pauseScanButton = null;
    private TokenGenMessagesTable tokenGenMessagesTable = null;
    private JProgressBar progressBar = null;
    private JButton loadButton = null;
    private JButton saveButton = null;
    private JButton optionsButton;

    // Disabled
    // private HttpPanel requestPanel = null;
    // private HttpPanel responsePanel = null;

    private ScanStatus scanStatus = null;

    private static Logger log = Logger.getLogger(TokenPanel.class);

    public TokenPanel(ExtensionTokenGen extension, TokenParam tokenParam) {
        super();
        this.extension = extension;
        this.setLayout(new CardLayout());
        this.setSize(474, 251);
        this.setName(extension.getMessages().getString("tokengen.panel.title"));
        this.setIcon(new ImageIcon(getClass().getResource("/resource/icon/fugue/barcode.png")));
        this.setDefaultAccelerator(
                this.extension
                        .getView()
                        .getMenuShortcutKeyStroke(KeyEvent.VK_T, KeyEvent.SHIFT_DOWN_MASK, false));
        this.setMnemonic(Constant.messages.getChar("tokengen.panel.mnemonic"));
        this.add(getPanelCommand(), getPanelCommand().getName());

        scanStatus =
                new ScanStatus(
                        new ImageIcon(getClass().getResource("/resource/icon/fugue/barcode.png")),
                        extension.getMessages().getString("tokengen.panel.title"));

        View.getSingleton()
                .getMainFrame()
                .getMainFooterPanel()
                .addFooterToolbarRightLabel(scanStatus.getCountLabel());
    }

    /**
     * This method initializes panelCommand
     *
     * @return javax.swing.JPanel
     */
    private javax.swing.JPanel getPanelCommand() {
        if (panelCommand == null) {

            panelCommand = new javax.swing.JPanel();
            panelCommand.setLayout(new java.awt.GridBagLayout());
            panelCommand.setName("TokenGen");

            GridBagConstraints gridBagConstraints1 = new GridBagConstraints();
            GridBagConstraints gridBagConstraints2 = new GridBagConstraints();

            gridBagConstraints1.gridx = 0;
            gridBagConstraints1.gridy = 0;
            gridBagConstraints1.insets = new java.awt.Insets(2, 2, 2, 2);
            gridBagConstraints1.anchor = java.awt.GridBagConstraints.NORTHWEST;
            gridBagConstraints1.fill = java.awt.GridBagConstraints.HORIZONTAL;
            gridBagConstraints1.weightx = 1.0D;

            gridBagConstraints2.gridx = 0;
            gridBagConstraints2.gridy = 1;
            gridBagConstraints2.weightx = 1.0;
            gridBagConstraints2.weighty = 1.0;
            gridBagConstraints2.fill = java.awt.GridBagConstraints.BOTH;
            gridBagConstraints2.insets = new java.awt.Insets(0, 0, 0, 0);
            gridBagConstraints2.anchor = java.awt.GridBagConstraints.NORTHWEST;

            panelCommand.add(this.getPanelToolbar(), gridBagConstraints1);
            panelCommand.add(getJScrollPane(), gridBagConstraints2);
        }
        return panelCommand;
    }
    /**/

    private javax.swing.JToolBar getPanelToolbar() {
        if (panelToolbar == null) {

            panelToolbar = new javax.swing.JToolBar();
            panelToolbar.setLayout(new java.awt.GridBagLayout());
            panelToolbar.setEnabled(true);
            panelToolbar.setFloatable(false);
            panelToolbar.setRollover(true);
            panelToolbar.setPreferredSize(new java.awt.Dimension(800, 30));
            panelToolbar.setFont(FontUtils.getFont("Dialog"));
            panelToolbar.setName("TokenToolbar");

            GridBagConstraints gridBagConstraints5 = new GridBagConstraints();
            GridBagConstraints gridBagConstraints6 = new GridBagConstraints();
            GridBagConstraints gridBagConstraints7 = new GridBagConstraints();
            GridBagConstraints gridBagConstraints8 = new GridBagConstraints();
            GridBagConstraints gridBagConstraints9 = new GridBagConstraints();
            GridBagConstraints gridBagConstraints10 = new GridBagConstraints();
            // Dummy
            GridBagConstraints gridBagConstraintsx = new GridBagConstraints();

            gridBagConstraints5.gridx = 4;
            gridBagConstraints5.gridy = 0;
            gridBagConstraints5.insets = new java.awt.Insets(0, 0, 0, 0);
            gridBagConstraints5.anchor = java.awt.GridBagConstraints.WEST;

            gridBagConstraints6.gridx = 5;
            gridBagConstraints6.gridy = 0;
            gridBagConstraints6.insets = new java.awt.Insets(0, 0, 0, 0);
            gridBagConstraints6.anchor = java.awt.GridBagConstraints.WEST;

            gridBagConstraints7.gridx = 6;
            gridBagConstraints7.gridy = 0;
            gridBagConstraints7.insets = new java.awt.Insets(0, 0, 0, 0);
            gridBagConstraints7.anchor = java.awt.GridBagConstraints.WEST;

            gridBagConstraints8.gridx = 7;
            gridBagConstraints8.gridy = 0;
            gridBagConstraints8.weightx = 1.0;
            gridBagConstraints8.weighty = 1.0;
            gridBagConstraints8.insets = new java.awt.Insets(0, 5, 0, 5); // Slight indent
            gridBagConstraints8.anchor = java.awt.GridBagConstraints.WEST;
            gridBagConstraints8.fill = java.awt.GridBagConstraints.HORIZONTAL;

            gridBagConstraints9.gridx = 8;
            gridBagConstraints9.gridy = 0;
            gridBagConstraints9.insets = new java.awt.Insets(0, 0, 0, 0);
            gridBagConstraints9.anchor = java.awt.GridBagConstraints.EAST;

            gridBagConstraints10.gridx = 9;
            gridBagConstraints10.gridy = 0;
            gridBagConstraints10.insets = new java.awt.Insets(0, 0, 0, 0);
            gridBagConstraints10.anchor = java.awt.GridBagConstraints.EAST;

            gridBagConstraintsx.gridx = 10;
            gridBagConstraintsx.gridy = 0;
            gridBagConstraintsx.weightx = 1.0;
            gridBagConstraintsx.weighty = 1.0;
            gridBagConstraintsx.insets = new java.awt.Insets(0, 0, 0, 0);
            gridBagConstraintsx.anchor = java.awt.GridBagConstraints.WEST;

            JLabel t1 = new JLabel();

            panelToolbar.add(getPauseScanButton(), gridBagConstraints6);
            panelToolbar.add(getStopScanButton(), gridBagConstraints7);
            panelToolbar.add(getProgressBar(), gridBagConstraints8);
            panelToolbar.add(getLoadButton(), gridBagConstraints9);
            panelToolbar.add(getSaveButton(), gridBagConstraints10);

            panelToolbar.add(t1, gridBagConstraintsx);
            panelToolbar.add(getOptionsButton());
        }
        return panelToolbar;
    }

    private JProgressBar getProgressBar() {
        if (progressBar == null) {
            progressBar = new JProgressBar(0, 100); // Max will change as scan progresses
            progressBar.setValue(0);
            progressBar.setStringPainted(true);
            progressBar.setEnabled(false);
        }
        return progressBar;
    }

    private JButton getStopScanButton() {
        if (stopScanButton == null) {
            stopScanButton = new JButton();
            stopScanButton.setToolTipText(
                    extension.getMessages().getString("tokengen.toolbar.button.stop"));
            stopScanButton.setIcon(
                    new ImageIcon(getClass().getResource("/resource/icon/16/142.png")));
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

    private JToggleButton getPauseScanButton() {
        if (pauseScanButton == null) {
            pauseScanButton = new ZapToggleButton();
            pauseScanButton.setToolTipText(
                    extension.getMessages().getString("tokengen.toolbar.button.pause"));
            pauseScanButton.setSelectedToolTipText(
                    extension.getMessages().getString("tokengen.toolbar.button.unpause"));
            pauseScanButton.setIcon(
                    new ImageIcon(getClass().getResource("/resource/icon/16/141.png")));
            pauseScanButton.setRolloverIcon(
                    new ImageIcon(getClass().getResource("/resource/icon/16/141.png")));
            pauseScanButton.setSelectedIcon(
                    new ImageIcon(getClass().getResource("/resource/icon/16/131.png")));
            pauseScanButton.setRolloverSelectedIcon(
                    new ImageIcon(getClass().getResource("/resource/icon/16/131.png")));
            pauseScanButton.setEnabled(false);
            pauseScanButton.addActionListener(
                    new ActionListener() {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                            pauseScan();
                        }
                    });
        }
        return pauseScanButton;
    }

    private JButton getLoadButton() {
        if (loadButton == null) {
            loadButton = new JButton();
            loadButton.setToolTipText(
                    extension.getMessages().getString("tokengen.toolbar.button.load"));
            loadButton.setIcon(new ImageIcon(getClass().getResource("/resource/icon/16/047.png")));
            loadButton.setEnabled(true);
            loadButton.addActionListener(
                    new ActionListener() {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                            loadTokens();
                        }
                    });
        }
        return loadButton;
    }

    private JButton getSaveButton() {
        if (saveButton == null) {
            saveButton = new JButton();
            saveButton.setToolTipText(
                    extension.getMessages().getString("tokengen.toolbar.button.save"));
            saveButton.setIcon(new ImageIcon(getClass().getResource("/resource/icon/16/096.png")));
            saveButton.setEnabled(false);
            saveButton.addActionListener(
                    new ActionListener() {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                            saveTokens();
                        }
                    });
        }
        return saveButton;
    }

    private JButton getOptionsButton() {
        if (optionsButton == null) {
            optionsButton =
                    new JButton(
                            DisplayUtils.getScaledIcon(
                                    TokenPanel.class.getResource("/resource/icon/16/041.png")));
            optionsButton.setToolTipText(
                    Constant.messages.getString("tokengen.toolbar.button.options"));
            optionsButton.addActionListener(
                    e ->
                            Control.getSingleton()
                                    .getMenuToolsControl()
                                    .options(
                                            Constant.messages.getString(
                                                    "tokengen.optionspanel.name")));
        }
        return optionsButton;
    }

    private JScrollPane getJScrollPane() {
        if (jScrollPane == null) {
            jScrollPane = new JScrollPane();
            jScrollPane.setViewportView(getInitialMessage());
            jScrollPane.setFont(FontUtils.getFont("Dialog"));
        }
        return jScrollPane;
    }

    private JTextPane getInitialMessage() {
        if (initialMessage == null) {
            initialMessage = new JTextPane();
            initialMessage.setEditable(false);
            initialMessage.setFont(FontUtils.getFont("Dialog"));
            initialMessage.setContentType("text/html");
            initialMessage.setText(
                    extension.getMessages().getString("tokengen.label.initialMessage"));
        }

        return initialMessage;
    }

    private void resetTokenResultList() {
        resultsModel.clear();
    }

    public int getTokenResultsSize() {
        return this.resultsModel.getRowCount();
    }

    protected void addTokenResult(final MessageSummary msg) {

        if (EventQueue.isDispatchThread()) {
            resultsModel.addMessage(msg);
            if (msg.isGoodResponse()) {
                getProgressBar().setValue(getProgressBar().getValue() + 1);
            }
            return;
        }
        try {
            EventQueue.invokeLater(
                    new Runnable() {
                        @Override
                        public void run() {
                            addTokenResult(msg);
                        }
                    });
        } catch (Exception e) {
        }
    }

    private TokenGenMessagesTable getTokenGenMessagesTable() {
        if (tokenGenMessagesTable == null) {
            tokenGenMessagesTable = new TokenGenMessagesTable(resultsModel);
            tokenGenMessagesTable.setName(RESULTS_TABLE_NAME);

            // TODO Allow to show the messages in the request/response panels?
            // we would either have to cache all the messages (which is expensive in memory)
            // or store all the messages in the db, which is slow
        }
        return tokenGenMessagesTable;
    }

    private void stopScan() {
        log.debug("Stopping token generation");
        extension.stopTokenGeneration();
    }

    private void loadTokens() {
        JFileChooser chooser =
                new JFileChooser(Model.getSingleton().getOptionsParam().getUserDirectory());
        int rc = chooser.showOpenDialog(View.getSingleton().getMainFrame());
        if (rc == JFileChooser.APPROVE_OPTION) {
            try {
                File file = chooser.getSelectedFile();
                if (file == null) {
                    return;
                }
                Model.getSingleton()
                        .getOptionsParam()
                        .setUserDirectory(chooser.getCurrentDirectory());

                CharacterFrequencyMap cfm = new CharacterFrequencyMap();
                cfm.load(file);
                this.extension.showAnalyseTokensDialog(cfm);

            } catch (Exception e) {
                View.getSingleton()
                        .showWarningDialog(
                                extension.getMessages().getString("tokengen.generate.load.error"));
                log.error(e.getMessage(), e);
            }
        }
    }

    private void saveTokens() {
        JFileChooser chooser =
                new WritableFileChooser(Model.getSingleton().getOptionsParam().getUserDirectory());
        File file = null;
        int rc = chooser.showSaveDialog(View.getSingleton().getMainFrame());
        if (rc == JFileChooser.APPROVE_OPTION) {
            try {
                file = chooser.getSelectedFile();
                if (file == null) {
                    return;
                }

                CharacterFrequencyMap cfm = new CharacterFrequencyMap();

                for (int i = 0; i < this.resultsModel.getRowCount(); i++) {
                    MessageSummary msg = this.resultsModel.getMessage(i);
                    if (msg.getToken() != null) {
                        cfm.addToken(msg.getToken());
                    }
                }

                cfm.save(file);

            } catch (Exception e) {
                View.getSingleton()
                        .showWarningDialog(
                                extension.getMessages().getString("tokengen.generate.save.error"));
                log.error(e.getMessage(), e);
            }
        }
    }

    private void pauseScan() {
        if (getPauseScanButton().getModel().isSelected()) {
            log.debug("Pausing token generation");
            extension.pauseTokenGeneration();
        } else {
            log.debug("Resuming token generation");
            extension.resumeTokenGeneration();
        }
    }

    public void scanStarted(int reqCount) {
        getProgressBar().setValue(0);
        getProgressBar().setMaximum(reqCount);

        this.getJScrollPane().setViewportView(getTokenGenMessagesTable());
        this.setTabFocus();
        resetTokenResultList();

        getProgressBar().setEnabled(true);
        getStopScanButton().setEnabled(true);
        getPauseScanButton().setEnabled(true);
        getSaveButton().setEnabled(false);
        scanStatus.incScanCount();
    }

    public void scanFinshed() {
        getStopScanButton().setEnabled(false);
        getPauseScanButton().setEnabled(false);
        getPauseScanButton().setSelected(false);
        if (getTokenResultsSize() > 0) {
            getSaveButton().setEnabled(true);
        }
        getProgressBar().setEnabled(false);
        scanStatus.decScanCount();
    }

    public void reset() {
        getJScrollPane().setViewportView(getInitialMessage());
        resetTokenResultList();
        getSaveButton().setEnabled(false);
        getStopScanButton().setEnabled(false);
        getPauseScanButton().setEnabled(false);
        getPauseScanButton().setSelected(false);
        getProgressBar().setEnabled(false);
        getProgressBar().setValue(0);
    }

    public void setDisplayPanel(HttpPanel requestPanel, HttpPanel responsePanel) {
        // this.requestPanel = requestPanel;
        // this.responsePanel = responsePanel;

    }

    ScanStatus getScanStatus() {
        return scanStatus;
    }
}
