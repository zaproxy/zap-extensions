/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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
package org.zaproxy.zap.extension.regextester.ui;

import java.awt.BorderLayout;
import java.awt.Dimension;
import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import javax.swing.text.BadLocationException;
import javax.swing.text.DefaultHighlighter;
import javax.swing.text.Highlighter;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.regextester.RegexTestInput;
import org.zaproxy.zap.extension.regextester.RegexTestResult;
import org.zaproxy.zap.extension.regextester.RegexTester;
import org.zaproxy.zap.extension.regextester.ui.model.RegexModel;

@SuppressWarnings("serial")
public class MatchPanel extends JPanel {

    private static final long serialVersionUID = 1L;

    private static final String MATCHES_LABEL =
            Constant.messages.getString("regextester.dialog.matches");
    private static final String LOOKING_AT_LABEL =
            Constant.messages.getString("regextester.dialog.lookingat");
    private static final String MATCH_RESULT_HEADER =
            Constant.messages.getString("regextester.dialog.matchresultheader");
    private static final String FIND_RESULT_HEADER =
            Constant.messages.getString("regextester.dialog.findresultheader");
    private static final String FIND_CAPTURE_HEADER =
            Constant.messages.getString("regextester.dialog.findcaptureheader");

    private final DefaultHighlighter.DefaultHighlightPainter highlightPainter =
            new DefaultHighlighter.DefaultHighlightPainter(null);
    private final JTextArea resultField;
    private final JTextArea captureField;
    private final JLabel matchField;
    private final JLabel lookingAtField;
    private RegexModel regexModel;

    public MatchPanel(RegexModel regexModel) {
        super(new BorderLayout());
        this.regexModel = regexModel;

        resultField = createTextArea();
        captureField = createTextArea();
        matchField = new JLabel();
        matchField.setText(String.format(MATCHES_LABEL, ""));
        lookingAtField = new JLabel();
        lookingAtField.setText(String.format(LOOKING_AT_LABEL, ""));

        JPanel matchPanel = createPanel(MATCH_RESULT_HEADER);
        matchPanel.add(matchField, BorderLayout.NORTH);
        matchPanel.add(lookingAtField, BorderLayout.SOUTH);
        matchPanel.setPreferredSize(new Dimension(0, 80));

        JPanel findPanel = createPanel(resultField, FIND_RESULT_HEADER);
        JPanel capturePanel = createPanel(captureField, FIND_CAPTURE_HEADER);

        JSplitPane findSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, findPanel, capturePanel);
        findSplit.setResizeWeight(0.35);
        findSplit.setBorder(BorderFactory.createEmptyBorder());

        add(matchPanel, BorderLayout.NORTH);
        add(findSplit, BorderLayout.CENTER);
    }

    private JPanel createPanel(JTextArea resultField, String title) {
        JPanel resultPanel = createPanel(title);
        resultPanel.add(new JScrollPane(resultField), BorderLayout.CENTER);
        return resultPanel;
    }

    private JPanel createPanel(String title) {
        JPanel resultPanel = new JPanel(new BorderLayout());
        resultPanel.setBorder(RegexDialog.createBorder(title));
        return resultPanel;
    }

    private JTextArea createTextArea() {
        JTextArea textArea = new JTextArea();
        textArea.setFont(RegexDialog.monoFont);
        textArea.setLineWrap(true);
        textArea.setWrapStyleWord(true);
        textArea.setEditable(false);
        return textArea;
    }

    public void updateFromModel() {
        SwingUtilities.invokeLater(this::update);
    }

    private void update() {
        if (regexModel.getRegex() == null || regexModel.getTestValue() == null) {
            return;
        }

        RegexTestInput input = new RegexTestInput(regexModel.getRegex(), regexModel.getTestValue());
        RegexTestResult result = RegexTester.test(input);

        matchField.setText(String.format(MATCHES_LABEL, result.isMatch()));
        lookingAtField.setText(String.format(LOOKING_AT_LABEL, result.isLookingAt()));
        resultField.setText(result.getResult());
        captureField.setText(result.getCapture());
        captureField.setCaretPosition(0);

        Highlighter highlighter = resultField.getHighlighter();
        for (RegexTestResult.Group group : result.getGroups()) {
            try {
                highlighter.addHighlight(group.getStart(), group.getEnd(), highlightPainter);
            } catch (BadLocationException ignore) {
            }
        }
    }
}
