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

import java.awt.BorderLayout;
import java.awt.EventQueue;
import java.awt.event.ActionEvent;
import java.awt.event.ItemEvent;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;
import java.util.Locale;
import javax.swing.AbstractAction;
import javax.swing.Box;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JToolBar;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVPrinter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.fuzz.FuzzResultsContentPanel;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.HttpFuzzer;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.HttpFuzzerListener;
import org.zaproxy.zap.view.ZapToggleButton;
import org.zaproxy.zap.view.widgets.WritableFileChooser;

public class HttpFuzzResultsContentPanel extends JPanel
        implements FuzzResultsContentPanel<HttpMessage, HttpFuzzer> {

    private static final long serialVersionUID = -2258680877665356649L;

    public static final String RESULTS_PANEL_NAME = "fuzz.httpfuzzerResultsContentPanel";
    public static final String ERRORS_PANEL_NAME = "fuzz.httpfuzzerErrorsContentPanel";

    private static final Logger logger = LogManager.getLogger(HttpFuzzResultsContentPanel.class);
    private static final String CSV_EXTENSION = ".csv";

    private static final HttpFuzzerResultsTableModel EMPTY_RESULTS_MODEL =
            new HttpFuzzerResultsTableModel();
    private static final HttpFuzzerErrorsTableModel EMPTY_ERRORS_MODEL =
            new HttpFuzzerErrorsTableModel();

    private JToolBar toolbar;
    private JLabel messageCountLabel;
    private JLabel messageCountValueLabel;
    private JLabel errorCountLabel;
    private JLabel errorCountValueLabel;
    private ZapToggleButton showErrorsToggleButton;

    private JPanel mainPanel;

    private JTabbedPane tabbedPane;

    private JScrollPane fuzzResultTableScrollPane;
    private HttpFuzzerResultsTable fuzzResultTable;

    private JScrollPane errorsTableScrollPane;
    private HttpFuzzerErrorsTable errorsTable;

    private HttpFuzzer currentFuzzer;
    private HttpFuzzerListener httpFuzzerListener;

    public HttpFuzzResultsContentPanel() {
        super(new BorderLayout());

        tabbedPane = new JTabbedPane();

        toolbar = new JToolBar();
        toolbar.setFloatable(false);
        toolbar.setRollover(true);

        messageCountLabel =
                new JLabel(
                        Constant.messages.getString(
                                "fuzz.httpfuzzer.results.toolbar.messagesSent"));
        messageCountValueLabel = new JLabel("0");

        errorCountLabel =
                new JLabel(Constant.messages.getString("fuzz.httpfuzzer.results.toolbar.errors"));
        errorCountValueLabel = new JLabel("0");

        showErrorsToggleButton =
                new ZapToggleButton(
                        Constant.messages.getString(
                                "fuzz.httpfuzzer.results.toolbar.button.showErrors.label"));
        showErrorsToggleButton.setEnabled(false);
        showErrorsToggleButton.setToolTipText(
                Constant.messages.getString(
                        "fuzz.httpfuzzer.results.toolbar.button.showErrors.tooltip"));
        showErrorsToggleButton.setSelectedToolTipText(
                Constant.messages.getString(
                        "fuzz.httpfuzzer.results.toolbar.button.showErrors.tooltip.selected"));
        showErrorsToggleButton.setDisabledToolTipText(
                Constant.messages.getString(
                        "fuzz.httpfuzzer.results.toolbar.button.showErrors.tooltip.disabled"));
        showErrorsToggleButton.setIcon(
                new ImageIcon(
                        HttpFuzzResultsContentPanel.class.getResource(
                                "/resource/icon/16/050.png")));
        showErrorsToggleButton.addItemListener(
                e -> {
                    if (ItemEvent.SELECTED == e.getStateChange()) {
                        showTabs();
                    } else {
                        hideErrorsTab();
                    }
                });

        toolbar.add(Box.createHorizontalStrut(4));
        toolbar.add(messageCountLabel);
        toolbar.add(Box.createHorizontalStrut(4));
        toolbar.add(messageCountValueLabel);
        toolbar.add(Box.createHorizontalStrut(32));

        toolbar.add(errorCountLabel);
        toolbar.add(Box.createHorizontalStrut(4));
        toolbar.add(errorCountValueLabel);

        toolbar.add(Box.createHorizontalStrut(16));
        toolbar.add(showErrorsToggleButton);

        JButton button =
                new JButton(
                        Constant.messages.getString(
                                "fuzz.httpfuzzer.results.toolbar.button.export"));
        button.setIcon(
                new ImageIcon(
                        HttpFuzzResultsContentPanel.class.getResource(
                                "/resource/icon/16/115.png")));
        button.addActionListener(
                (new AbstractAction() {
                    private static final long serialVersionUID = 1L;

                    @Override
                    public void actionPerformed(ActionEvent e) {
                        WritableFileChooser chooser =
                                new WritableFileChooser(
                                        Model.getSingleton().getOptionsParam().getUserDirectory()) {

                                    private static final long serialVersionUID =
                                            -1660943014924270012L;

                                    @Override
                                    public void approveSelection() {
                                        File file = getSelectedFile();
                                        if (file != null) {
                                            String filePath = file.getAbsolutePath();
                                            if (!filePath.toLowerCase(Locale.ROOT)
                                                    .endsWith(CSV_EXTENSION)) {
                                                setSelectedFile(new File(filePath + CSV_EXTENSION));
                                            }
                                        }

                                        super.approveSelection();
                                    }
                                };
                        chooser.setSelectedFile(
                                new File(
                                        Constant.messages.getString(
                                                "fuzz.httpfuzzer.results.toolbar.button.export.defaultName")));
                        if (chooser.showSaveDialog(View.getSingleton().getMainFrame())
                                == WritableFileChooser.APPROVE_OPTION) {

                            boolean success = true;
                            try (CSVPrinter pw =
                                    new CSVPrinter(
                                            Files.newBufferedWriter(
                                                    chooser.getSelectedFile().toPath(),
                                                    StandardCharsets.UTF_8),
                                            CSVFormat.DEFAULT)) {
                                pw.printRecord(currentFuzzer.getMessagesModel().getHeaders());
                                int count = currentFuzzer.getMessagesModel().getRowCount();
                                for (int i = 0; i < count; i++) {
                                    List<Object> valueOfRow =
                                            currentFuzzer
                                                    .getMessagesModel()
                                                    .getEntry(i)
                                                    .getValuesOfHeaders();
                                    String customStateValue =
                                            fuzzResultTable.getCustomStateValue(
                                                    currentFuzzer
                                                            .getMessagesModel()
                                                            .getEntry(i)
                                                            .getCustomStates());
                                    valueOfRow.add(13, customStateValue);
                                    pw.printRecord(valueOfRow);
                                }
                            } catch (Exception ex) {
                                success = false;
                                JOptionPane.showMessageDialog(
                                        View.getSingleton().getMainFrame(),
                                        Constant.messages.getString(
                                                        "fuzz.httpfuzzer.results.toolbar.button.export.showMessageError")
                                                + "\n"
                                                + ex.getLocalizedMessage());
                                logger.error("Export Failed: {}", ex);
                            }
                            // Delay the presentation of success message, to ensure all the data was
                            // already flushed.
                            if (success) {
                                JOptionPane.showMessageDialog(
                                        View.getSingleton().getMainFrame(),
                                        Constant.messages.getString(
                                                "fuzz.httpfuzzer.results.toolbar.button.export.showMessageSuccessful"));
                            }
                        }
                    }
                }));
        toolbar.add(Box.createHorizontalGlue());
        toolbar.add(button);
        mainPanel = new JPanel(new BorderLayout());

        fuzzResultTable = new HttpFuzzerResultsTable(RESULTS_PANEL_NAME, EMPTY_RESULTS_MODEL);
        errorsTable = new HttpFuzzerErrorsTable(ERRORS_PANEL_NAME, EMPTY_ERRORS_MODEL);

        fuzzResultTableScrollPane = new JScrollPane();
        fuzzResultTableScrollPane.setViewportView(fuzzResultTable);

        errorsTableScrollPane = new JScrollPane();
        errorsTableScrollPane.setViewportView(errorsTable);

        mainPanel.add(fuzzResultTableScrollPane);

        add(toolbar, BorderLayout.PAGE_START);
        add(mainPanel, BorderLayout.CENTER);
    }

    private void hideErrorsTab() {
        showErrorsToggleButton.setSelected(false);
        showErrorsToggleButton.setText(
                Constant.messages.getString(
                        "fuzz.httpfuzzer.results.toolbar.button.showErrors.label"));
        tabbedPane.removeAll();
        mainPanel.removeAll();

        mainPanel.add(fuzzResultTableScrollPane);
        mainPanel.revalidate();
    }

    private void showTabs() {
        mainPanel.removeAll();

        tabbedPane.addTab(
                Constant.messages.getString("fuzz.httpfuzzer.results.tab.messages"),
                fuzzResultTableScrollPane);
        tabbedPane.addTab(
                Constant.messages.getString("fuzz.httpfuzzer.results.tab.errors"),
                errorsTableScrollPane);
        showErrorsToggleButton.setText(
                Constant.messages.getString(
                        "fuzz.httpfuzzer.results.toolbar.button.showErrors.label.selected"));
        tabbedPane.setSelectedIndex(1);

        mainPanel.add(tabbedPane);
        mainPanel.revalidate();
        mainPanel.repaint();
    }

    @Override
    public JPanel getPanel() {
        return this;
    }

    @Override
    public void clear() {
        if (!EventQueue.isDispatchThread()) {
            try {
                EventQueue.invokeAndWait(this::clear);
            } catch (Exception e) {
                logger.error(e.getMessage(), e);
            }
            return;
        }

        currentFuzzer = null;
        fuzzResultTable.setModel(EMPTY_RESULTS_MODEL);
        errorsTable.setModel(EMPTY_ERRORS_MODEL);
    }

    public void clear(HttpFuzzer fuzzer) {
        if (currentFuzzer == fuzzer) {
            clear();
        }
    }

    @Override
    public void showFuzzerResults(HttpFuzzer fuzzer) {
        if (currentFuzzer != null) {
            currentFuzzer.removeHttpFuzzerListener(getHttpFuzzerListener());
        }
        currentFuzzer = fuzzer;

        messageCountValueLabel.setText(Integer.toString(currentFuzzer.getMessagesSentCount()));
        int errorCount = currentFuzzer.getErrorCount();
        errorCountValueLabel.setText(Integer.toString(errorCount));
        if (errorCount == 0 && showErrorsToggleButton.isSelected()) {
            hideErrorsTab();
        }
        showErrorsToggleButton.setEnabled(errorCount != 0);

        currentFuzzer.addHttpFuzzerListener(getHttpFuzzerListener());

        errorsTable.setModel(currentFuzzer.getErrorsModel());
        fuzzResultTable.setModel(currentFuzzer.getMessagesModel());
    }

    public void addFuzzResultStateHighlighter(HttpFuzzerResultStateHighlighter highlighter) {
        fuzzResultTable.addFuzzResultStateHighlighter(highlighter);
    }

    public void removeFuzzResultStateHighlighter(HttpFuzzerResultStateHighlighter highlighter) {
        fuzzResultTable.removeFuzzResultStateHighlighter(highlighter);
    }

    private HttpFuzzerListener getHttpFuzzerListener() {
        if (httpFuzzerListener == null) {
            httpFuzzerListener = new HttpFuzzerListenerImpl();
        }
        return httpFuzzerListener;
    }

    private class HttpFuzzerListenerImpl implements HttpFuzzerListener {

        @Override
        public void messageSent(int total) {
            messageCountValueLabel.setText(Integer.toString(total));
        }

        @Override
        public void errorFound(int total) {
            errorCountValueLabel.setText(Integer.toString(total));
            if (!showErrorsToggleButton.isEnabled()) {
                showErrorsToggleButton.setEnabled(true);
            }
        }
    }
}
