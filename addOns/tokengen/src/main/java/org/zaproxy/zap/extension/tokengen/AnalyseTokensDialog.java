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

import java.awt.Component;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.HeadlessException;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.util.List;
import java.util.ResourceBundle;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JProgressBar;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jdesktop.swingx.JXTable;
import org.parosproxy.paros.extension.AbstractDialog;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.utils.FontUtils;
import org.zaproxy.zap.view.widgets.WritableFileChooser;

@SuppressWarnings("serial")
public class AnalyseTokensDialog extends AbstractDialog implements TokenAnalyserListenner {

    private static final long serialVersionUID = 1L;

    private JPanel jPanel = null;
    private JTabbedPane jTabbed = null;
    private JPanel jTabPanel1 = null;
    private JPanel jTabPanel2 = null;
    private JPanel jTabPanel3 = null;

    private JXTable tableTests = null;
    private TokenAnalysisResultsTableModel testTableModel = null;
    private JScrollPane testsScrollPane = null;
    private JScrollPane detailsScrollPane = null;
    private JScrollPane errorsScrollPane = null;
    private TokenAnalysisDetailsArea detailsArea = null;
    private TokenAnalysisDetailsArea errorsArea = null;
    private JButton cancelButton = null;
    private JButton saveButton = null;
    private JProgressBar progressBar = null;

    TokenAnalyserThread analyserThread = null;

    private static Logger log = LogManager.getLogger(AnalyseTokensDialog.class);

    private ResourceBundle messages;

    /** @throws HeadlessException */
    public AnalyseTokensDialog(ResourceBundle messages) throws HeadlessException {
        super(View.getSingleton().getMainFrame(), false);
        this.messages = messages;
        initialize();
    }

    /** This method initializes this */
    private void initialize() {
        this.setContentPane(getJPanel());
        this.setTitle(messages.getString("tokengen.analyse.title"));
        this.setSize(500, 450);
    }

    /**
     * This method initializes jPanel
     *
     * @return javax.swing.JPanel
     */
    private JPanel getJPanel() {
        if (jPanel == null) {
            jPanel = new JPanel();
            jPanel.setLayout(new GridBagLayout());

            jTabbed = new JTabbedPane();
            jTabbed.setPreferredSize(new java.awt.Dimension(800, 500));

            jTabPanel1 = new JPanel();
            jTabPanel1.setLayout(new GridBagLayout());

            jTabPanel2 = new JPanel();
            jTabPanel2.setLayout(new GridBagLayout());

            jTabPanel3 = new JPanel();
            jTabPanel3.setLayout(new GridBagLayout());

            jTabbed.addTab(messages.getString("tokengen.analyse.tab.summary"), jTabPanel1);
            jTabbed.addTab(messages.getString("tokengen.analyse.tab.errors"), jTabPanel2);
            jTabbed.addTab(messages.getString("tokengen.analyse.tab.details"), jTabPanel3);

            jTabPanel1.add(getProgressBar(), getGBC(0, 0, 1, 1.0D, 0.0D));
            jTabPanel1.add(getTestsScrollPane(), getGBC(0, 1, 1, 1.0D, 1.0D));

            jTabPanel2.add(this.getErrorsScrollPane(), getGBC(0, 0, 1, 1.0D, 1.0D));

            jTabPanel3.add(this.getDetailsScrollPane(), getGBC(0, 0, 1, 1.0D, 1.0D));

            jPanel.add(jTabbed, getGBC(0, 0, 4, 1.0D, 1.0D));
            jPanel.add(getCancelButton(), getGBC(2, 1, 1, 0.25));
            jPanel.add(getSaveButton(), getGBC(3, 1, 1, 0.25));
        }
        return jPanel;
    }

    private JXTable getTableTests() {
        if (tableTests == null) {
            tableTests = new JXTable();
            tableTests.setModel(getTokenAnalysisResultsTableModel());
            tableTests.setRowHeight(18);
            tableTests.setIntercellSpacing(new java.awt.Dimension(1, 1));
            tableTests.setColumnControlVisible(true);

            tableTests.getColumnModel().getColumn(0).setPreferredWidth(300);
            tableTests.getColumnModel().getColumn(1).setPreferredWidth(20);
            tableTests.getColumnModel().getColumn(2).setPreferredWidth(100);
        }
        return tableTests;
    }

    private TokenAnalysisResultsTableModel getTokenAnalysisResultsTableModel() {
        if (testTableModel == null) {
            testTableModel = new TokenAnalysisResultsTableModel();
        }
        return testTableModel;
    }

    private JProgressBar getProgressBar() {
        if (progressBar == null) {
            progressBar = new JProgressBar(0, TokenAnalyserThread.NUM_TESTS);
            progressBar.setValue(0);
            progressBar.setStringPainted(true);
            progressBar.setEnabled(true);
        }
        return progressBar;
    }

    public void startAnalysis(CharacterFrequencyMap cfm) {
        this.requestFocus();
        analyserThread = new TokenAnalyserThread(messages);
        analyserThread.setCfm(cfm);
        analyserThread.addListenner(this);
        analyserThread.addOutputDestination(this.getDetailsArea());
        analyserThread.start();
    }

    public void stopAnalysis() {
        if (analyserThread != null) {
            analyserThread.cancel();
        }
    }

    @Override
    public void notifyTestResult(TokenAnalysisTestResult result) {
        log.debug("notifyTestResult {} {}", result.getType(), result.getResult().name());
        this.getTokenAnalysisResultsTableModel().addResult(result);
        this.addDetailTitle(result.getName());
        this.addDetails(result.getDetails());
        this.getDetailsArea().append("\n");

        if (result.getFailures() != null && result.getFailures().size() > 0) {
            this.addErrorTitle(result.getName());
            this.addErrors(result.getFailures());
            this.getErrorsArea().append("\n");
        }
        this.getProgressBar().setValue(this.getProgressBar().getValue() + 1);
    }

    private JButton getCancelButton() {
        if (cancelButton == null) {
            cancelButton = new JButton();
            cancelButton.setText(messages.getString("tokengen.button.cancel"));
            cancelButton.addActionListener(
                    e -> {
                        stopAnalysis();
                        setVisible(false);
                    });
        }
        return cancelButton;
    }

    private JButton getSaveButton() {
        if (saveButton == null) {
            saveButton = new JButton();
            saveButton.setText(messages.getString("tokengen.analyse.button.save"));
            saveButton.addActionListener(e -> saveAnalysis());
        }
        return saveButton;
    }

    private void saveAnalysis() {
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

                try (BufferedWriter out = new BufferedWriter(new FileWriter(file))) {
                    out.write(getErrorsArea().getText());
                    out.write(getDetailsArea().getText());
                }

            } catch (Exception e) {
                View.getSingleton()
                        .showWarningDialog(messages.getString("tokengen.analyse.save.error"));
                log.error(e.getMessage(), e);
            }
        }
    }

    private GridBagConstraints getGBC(int x, int y, int width, double weightx) {
        return this.getGBC(x, y, width, weightx, 0.0);
    }

    private GridBagConstraints getGBC(int x, int y, int width, double weightx, double weighty) {
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = x;
        gbc.gridy = y;
        gbc.insets = new java.awt.Insets(1, 5, 1, 5);
        gbc.anchor = java.awt.GridBagConstraints.NORTHWEST;
        gbc.fill = java.awt.GridBagConstraints.BOTH;
        gbc.weightx = weightx;
        gbc.weighty = weighty;
        gbc.gridwidth = width;
        return gbc;
    }

    public void setExtension(ExtensionTokenGen extension) {
        // this.extension = extension;
    }

    public void reset() {
        this.getProgressBar().setValue(0);
        this.getErrorsArea().setText("");
        this.getDetailsArea().setText("");
        this.getTokenAnalysisResultsTableModel().clear();
    }

    private JScrollPane getTestsScrollPane() {
        if (testsScrollPane == null) {
            testsScrollPane = new JScrollPane();
            testsScrollPane.setViewportView(getTableTests());
            testsScrollPane.setName("testsScrollPane");
        }
        return testsScrollPane;
    }

    private JScrollPane getDetailsScrollPane() {
        if (detailsScrollPane == null) {
            detailsScrollPane = new JScrollPane();
            detailsScrollPane.setViewportView(getDetailsArea());
            detailsScrollPane.setName("detailsScrollPane");
            // Looks wrong unless monospaced
            detailsScrollPane.setFont(FontUtils.getFont("Dialog"));
        }
        return detailsScrollPane;
    }

    private JScrollPane getErrorsScrollPane() {
        if (errorsScrollPane == null) {
            errorsScrollPane = new JScrollPane();
            errorsScrollPane.setViewportView(getErrorsArea());
            errorsScrollPane.setName("detailsScrollPane");
            // Looks wrong unless monospaced
            errorsScrollPane.setFont(FontUtils.getFont("Dialog"));
        }
        return errorsScrollPane;
    }
    /**
     * This method initializes txtOutput
     *
     * @return javax.swing.ZapTextArea
     */
    private TokenAnalysisDetailsArea getDetailsArea() {
        if (detailsArea == null) {
            detailsArea = new TokenAnalysisDetailsArea();
            detailsArea.setEditable(false);
            detailsArea.setLineWrap(false);
            detailsArea.setFont(FontUtils.getFont("Dialog"));
            detailsArea.setName("DetailsArea");
            detailsArea.setComponentPopupMenu(ZapPopupMenu.INSTANCE);
        }
        return detailsArea;
    }

    private TokenAnalysisDetailsArea getErrorsArea() {
        if (errorsArea == null) {
            errorsArea = new TokenAnalysisDetailsArea();
            errorsArea.setEditable(false);
            errorsArea.setLineWrap(false);
            errorsArea.setFont(FontUtils.getFont("Dialog"));
            errorsArea.setName("ErrorsArea");
            errorsArea.setComponentPopupMenu(ZapPopupMenu.INSTANCE);
        }
        return errorsArea;
    }

    private void addDetailTitle(String title) {
        if (title == null) {
            return;
        }
        String underline = new String(new char[title.length()]).replace('\0', '-');
        this.getDetailsArea().append(underline);
        this.getDetailsArea().append("\n");
        this.getDetailsArea().append(title);
        this.getDetailsArea().append("\n");
        this.getDetailsArea().append(underline);
        this.getDetailsArea().append("\n");
    }

    private void addErrorTitle(String title) {
        if (title == null) {
            return;
        }
        String underline = new String(new char[title.length()]).replace('\0', '-');
        this.getErrorsArea().append(underline);
        this.getErrorsArea().append("\n");
        this.getErrorsArea().append(title);
        this.getErrorsArea().append("\n");
        this.getErrorsArea().append(underline);
        this.getErrorsArea().append("\n");
    }

    private void addDetails(List<String> details) {
        if (details == null) {
            return;
        }
        for (String detail : details) {
            this.getDetailsArea().append(detail);
            this.getDetailsArea().append("\n");
        }
    }

    private void addErrors(List<String> errors) {
        if (errors == null) {
            return;
        }
        for (String error : errors) {
            this.getErrorsArea().append(error);
            this.getErrorsArea().append("\n");
        }
    }

    private static class ZapPopupMenu extends JPopupMenu {

        public static final ZapPopupMenu INSTANCE = new ZapPopupMenu();

        private static final long serialVersionUID = 1L;

        @Override
        public void show(Component invoker, int x, int y) {
            View.getSingleton().getPopupMenu().show(invoker, x, y);
        }
    }
}
