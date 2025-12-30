/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
package org.zaproxy.zap.extension.llmheader;

import java.awt.Component;
import java.awt.Dimension;
import java.util.List;
import java.util.Map;
import javax.swing.JOptionPane;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableColumnModel;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.view.popup.PopupMenuItemHttpMessageContainer;

public class LLMContextMenuItem extends PopupMenuItemHttpMessageContainer {

    private static final long serialVersionUID = 1L;
    private final transient LLMHeaderOptions options;

    public LLMContextMenuItem(LLMHeaderOptions options) {
        super(Constant.messages.getString("llmheader.context.menu"));
        this.options = options;
    }

    @Override
    public boolean isSafe() {
        return true;
    }

    @Override
    public void performAction(HttpMessage msg) {
        if ((options.getGeminiKey() == null || options.getGeminiKey().isEmpty())
                && (options.getBridgeUrl() == null || options.getBridgeUrl().isEmpty())) {
            String inputKey =
                    JOptionPane.showInputDialog(
                            View.getSingleton().getMainFrame(),
                            Constant.messages.getString("llmheader.dialog.apikey.prompt"),
                            Constant.messages.getString("llmheader.dialog.apikey.title"),
                            JOptionPane.QUESTION_MESSAGE);

            if (inputKey != null && !inputKey.trim().isEmpty()) {
                options.setGeminiKey(inputKey.trim());
            } else {
                return;
            }
        }

        new Thread(
                        () -> {
                            HttpHeader header = msg.getRequestHeader();
                            Map<String, String> headers =
                                    HeaderAnonymizer.anonymize(header, options.isAnonymize());

                            List<LLMIssue> issues =
                                    GeminiClient.analyze(
                                            headers,
                                            options.getBridgeUrl(),
                                            options.getGeminiKey(),
                                            options.getGeminiModel());

                            View.getSingleton()
                                    .getOutputPanel()
                                    .append(
                                            "LLM Analysis finished for "
                                                    + msg.getRequestHeader().getURI().toString()
                                                    + "\n");

                            if (!issues.isEmpty()) {
                                SwingUtilities.invokeLater(() -> showResultsDialog(issues));
                            } else {
                                SwingUtilities.invokeLater(
                                        () ->
                                                View.getSingleton()
                                                        .showWarningDialog("No issues found by LLM."));
                            }
                        })
                .start();
    }

    private void showResultsDialog(List<LLMIssue> issues) {
        String[] columnNames = {
            Constant.messages.getString("llmheader.dialog.issue"),
            Constant.messages.getString("llmheader.dialog.severity"),
            Constant.messages.getString("llmheader.dialog.confidence"),
            Constant.messages.getString("llmheader.dialog.recommendation")
        };

        Object[][] data = new Object[issues.size()][4];
        for (int i = 0; i < issues.size(); i++) {
            LLMIssue issue = issues.get(i);
            data[i][0] = issue.getIssue();
            data[i][1] = issue.getSeverity();
            data[i][2] = issue.getConfidence();
            data[i][3] = issue.getRecommendation();
        }

        JTable table = new JTable(data, columnNames);
        table.setRowHeight(80); // Increased row height for multi-line text
        
        TableColumnModel columnModel = table.getColumnModel();
        columnModel.getColumn(0).setPreferredWidth(150);
        columnModel.getColumn(1).setPreferredWidth(80);
        columnModel.getColumn(2).setPreferredWidth(80);
        columnModel.getColumn(3).setPreferredWidth(400);

        table.setDefaultRenderer(Object.class, new TextAreaRenderer());

        JScrollPane scrollPane = new JScrollPane(table);
        scrollPane.setPreferredSize(new Dimension(900, 500));

        JOptionPane.showMessageDialog(
                View.getSingleton().getMainFrame(),
                scrollPane,
                Constant.messages.getString("llmheader.dialog.title"),
                JOptionPane.INFORMATION_MESSAGE);
    }

    private static class TextAreaRenderer extends JTextArea implements TableCellRenderer {
        private static final long serialVersionUID = 1L;

        public TextAreaRenderer() {
            setLineWrap(true);
            setWrapStyleWord(true);
            setOpaque(true);
        }

        @Override
        public Component getTableCellRendererComponent(
                JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
            setText(value != null ? value.toString() : "");
            if (isSelected) {
                setForeground(table.getSelectionForeground());
                setBackground(table.getSelectionBackground());
            } else {
                setForeground(table.getForeground());
                setBackground(table.getBackground());
            }
            return this;
        }
    }
}
