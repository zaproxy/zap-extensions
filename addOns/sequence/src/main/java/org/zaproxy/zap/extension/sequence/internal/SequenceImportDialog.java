/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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
package org.zaproxy.zap.extension.sequence.internal;

import java.awt.Font;
import java.awt.Frame;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.text.AbstractDocument;
import javax.swing.text.AttributeSet;
import javax.swing.text.BadLocationException;
import javax.swing.text.DocumentFilter;
import org.apache.commons.lang3.StringUtils;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.AbstractDialog;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.exim.ExtensionExim;
import org.zaproxy.addon.exim.ImporterOptions;
import org.zaproxy.addon.exim.ImporterResult;
import org.zaproxy.zap.extension.script.ScriptType;
import org.zaproxy.zap.extension.zest.CreateScriptOptions;
import org.zaproxy.zap.extension.zest.ExtensionZest;
import org.zaproxy.zap.utils.FontUtils;
import org.zaproxy.zap.utils.Stats;
import org.zaproxy.zap.utils.ThreadUtils;
import org.zaproxy.zap.utils.ZapHtmlLabel;
import org.zaproxy.zap.utils.ZapLabel;
import org.zaproxy.zap.utils.ZapTextField;
import org.zaproxy.zap.view.LayoutHelper;

@SuppressWarnings("serial")
public class SequenceImportDialog extends AbstractDialog {

    private static final long serialVersionUID = 1L;

    private static final String STATS_PREFIX = "stats.sequence.gui.";

    private static final String MESSAGE_PREFIX = "sequence.importhar.";

    private final ScriptType scriptType;
    private final ExtensionExim exim;
    private final ExtensionZest zest;

    private ZapTextField fieldName;
    private ZapTextField fieldFile;
    private JCheckBox fieldAssertCode;
    private ZapTextField fieldAssertLength;
    private JButton buttonChooseFile;

    private JButton buttonCancel;
    private JButton buttonImport;
    private JProgressBar progressBar;

    public SequenceImportDialog(
            Frame parent, ScriptType scriptType, ExtensionExim exim, ExtensionZest zest) {
        super(parent, true);

        this.scriptType = scriptType;
        this.exim = exim;
        this.zest = zest;

        setTitle(Constant.messages.getString(MESSAGE_PREFIX + "title"));

        centreDialog();
        setLayout(new GridBagLayout());

        var fieldsPanel = new JPanel(new GridBagLayout());
        int fieldsRow = 0;

        fieldsPanel.add(
                new ZapLabel(Constant.messages.getString(MESSAGE_PREFIX + "labelName")),
                LayoutHelper.getGBC(0, fieldsRow, 1, 0.5, new Insets(0, 0, 4, 4)));
        fieldsPanel.add(
                getFieldName(), LayoutHelper.getGBC(1, fieldsRow, 2, 0.5, new Insets(4, 4, 4, 0)));

        fieldsRow++;
        var definitionLabel =
                new ZapHtmlLabel(
                        "<html>"
                                + Constant.messages.getString(MESSAGE_PREFIX + "labelFile")
                                + "<font color=red>*</font></html>");
        fieldsPanel.add(
                definitionLabel, LayoutHelper.getGBC(0, fieldsRow, 1, 0.5, new Insets(0, 0, 4, 4)));
        fieldsPanel.add(
                getFieldFile(), LayoutHelper.getGBC(1, fieldsRow, 1, 0.5, new Insets(0, 4, 4, 4)));
        fieldsPanel.add(
                getChooseFileButton(),
                LayoutHelper.getGBC(2, fieldsRow, 1, 0.5, new Insets(0, 4, 4, 0)));
        fieldsRow++;
        fieldsPanel.add(
                new JLabel(Constant.messages.getString(MESSAGE_PREFIX + "labelAssertCode")),
                LayoutHelper.getGBC(0, fieldsRow, 1, 0.5, new Insets(4, 0, 4, 4)));
        fieldsPanel.add(
                getFieldAssertCode(),
                LayoutHelper.getGBC(1, fieldsRow, 2, 0.5, new Insets(4, 4, 4, 0)));
        fieldsRow++;
        fieldsPanel.add(
                new JLabel(Constant.messages.getString(MESSAGE_PREFIX + "labelAssertLength")),
                LayoutHelper.getGBC(0, fieldsRow, 1, 0.5, new Insets(4, 0, 4, 4)));
        fieldsPanel.add(
                getFieldAssertLength(),
                LayoutHelper.getGBC(1, fieldsRow, 2, 0.5, new Insets(4, 4, 4, 0)));

        int row = 0;
        add(fieldsPanel, LayoutHelper.getGBC(0, row, 2, 1.0, new Insets(8, 8, 4, 8)));
        row++;
        var requiredFieldsLabel =
                new ZapHtmlLabel(
                        "<html><font color=red>*</font> "
                                + Constant.messages.getString(MESSAGE_PREFIX + "requiredFields")
                                + "</html>");
        Font font = requiredFieldsLabel.getFont();
        requiredFieldsLabel.setFont(FontUtils.getFont(font, FontUtils.Size.much_smaller));
        requiredFieldsLabel.setHorizontalAlignment(JLabel.RIGHT);
        add(requiredFieldsLabel, LayoutHelper.getGBC(0, row, 2, 1.0, new Insets(4, 8, 4, 8)));
        row++;
        add(getCancelButton(), LayoutHelper.getGBC(0, row, 1, 0.5, new Insets(4, 8, 8, 4)));
        add(getImportButton(), LayoutHelper.getGBC(1, row, 1, 0.5, new Insets(4, 4, 8, 8)));
        row++;
        add(getProgressBar(), LayoutHelper.getGBC(0, row, 2, 1.0, new Insets(0, 8, 8, 8)));
        pack();
        setDefaultCloseOperation(DISPOSE_ON_CLOSE);
    }

    private ZapTextField getFieldName() {
        if (fieldName == null) {
            fieldName = new ZapTextField(25);
        }
        return fieldName;
    }

    private ZapTextField getFieldFile() {
        if (fieldFile == null) {
            fieldFile = new ZapTextField(25);
        }
        return fieldFile;
    }

    private JCheckBox getFieldAssertCode() {
        if (fieldAssertCode == null) {
            fieldAssertCode = new JCheckBox();
        }
        return fieldAssertCode;
    }

    private ZapTextField getFieldAssertLength() {
        if (fieldAssertLength == null) {
            fieldAssertLength = new ZapTextField(25);
            ((AbstractDocument) fieldAssertLength.getDocument()).setDocumentFilter(new IntFilter());
        }
        return fieldAssertLength;
    }

    private void showWarningDialog(String message) {
        showProgressBar(false);
        View.getSingleton().showWarningDialog(this, message);
    }

    private void showWarningFileNotFound(String fileLocation) {
        showWarningDialog(
                Constant.messages.getString("openapi.import.error.fileNotFound", fileLocation));
    }

    void clearFields() {
        getFieldName().setText("");
        getFieldName().discardAllEdits();
        getFieldFile().setText("");
        getFieldFile().discardAllEdits();
        getFieldAssertCode().setSelected(false);
        getFieldAssertLength().setText("");
        getFieldAssertLength().discardAllEdits();
    }

    private JButton getChooseFileButton() {
        if (buttonChooseFile == null) {
            buttonChooseFile =
                    new JButton(Constant.messages.getString(MESSAGE_PREFIX + "chooseFileButton"));
            buttonChooseFile.addActionListener(
                    e -> {
                        JFileChooser filechooser =
                                new JFileChooser(
                                        Model.getSingleton().getOptionsParam().getUserDirectory());
                        int state = filechooser.showOpenDialog(this);
                        if (state == JFileChooser.APPROVE_OPTION) {
                            String filename = filechooser.getSelectedFile().getAbsolutePath();
                            try {
                                getFieldFile().setText(filename);
                                Model.getSingleton()
                                        .getOptionsParam()
                                        .setUserDirectory(filechooser.getCurrentDirectory());
                            } catch (Exception e1) {
                                showWarningFileNotFound(filename);
                            }
                        }
                    });
        }
        return buttonChooseFile;
    }

    private JButton getCancelButton() {
        if (buttonCancel == null) {
            buttonCancel = new JButton(Constant.messages.getString("all.button.cancel"));
            buttonCancel.addActionListener(
                    e -> {
                        dispose();
                        showProgressBar(false);
                    });
        }
        return buttonCancel;
    }

    private JButton getImportButton() {
        if (buttonImport == null) {
            buttonImport =
                    new JButton(Constant.messages.getString(MESSAGE_PREFIX + "importButton"));
            buttonImport.addActionListener(
                    e -> {
                        showProgressBar(true);
                        new Thread(
                                        () -> {
                                            if (importSequence()) {
                                                ThreadUtils.invokeAndWaitHandled(
                                                        () -> {
                                                            dispose();
                                                            showProgressBar(false);
                                                        });
                                            }
                                        },
                                        "ZAP-Sequence-UI-Import")
                                .start();
                    });
        }
        return buttonImport;
    }

    private JProgressBar getProgressBar() {
        if (progressBar == null) {
            progressBar = new JProgressBar();
            progressBar.setIndeterminate(true);
            progressBar.setVisible(false);
        }
        return progressBar;
    }

    private void showProgressBar(boolean show) {
        if (getProgressBar().isVisible() == show) {
            return;
        }

        setSize(getWidth(), getHeight() + (show ? 10 : -10));
        getProgressBar().setVisible(show);

        getImportButton().setEnabled(!show);
        getFieldName().setEnabled(!show);
        getFieldFile().setEnabled(!show);
        getChooseFileButton().setEnabled(!show);
        getFieldAssertCode().setEnabled(!show);
        getFieldAssertLength().setEnabled(!show);
    }

    private boolean importSequence() {
        String filePath = getFieldFile().getText();
        if (filePath == null || filePath.isEmpty()) {
            ThreadUtils.invokeAndWaitHandled(
                    () -> {
                        showWarningDialog(
                                Constant.messages.getString(MESSAGE_PREFIX + "error.missingFile"));
                        getFieldFile().requestFocusInWindow();
                    });
            return false;
        }

        Path file = Paths.get(filePath);
        String sequenceName = getFieldName().getText();
        if (StringUtils.isBlank(sequenceName)) {
            sequenceName = file.getFileName().toString().replaceFirst("(?i)\\.har$", "");
        }

        List<HttpMessage> messages = new ArrayList<>();
        List<String> errors = new ArrayList<>();
        ImporterResult result =
                exim.getImporter()
                        .apply(
                                ImporterOptions.builder()
                                        .setInputFile(file)
                                        .setMessageHandler(messages::add)
                                        .build());
        result.getErrors().forEach(errors::add);

        if (!errors.isEmpty()) {
            String message =
                    Constant.messages.getString(
                            "sequence.importhar.import.error", wrapEntriesInLiTags(errors));
            Stats.incCounter(STATS_PREFIX + "import.error");
            ThreadUtils.invokeAndWaitHandled(
                    () -> {
                        showProgressBar(false);
                        View.getSingleton().showMessageDialog(this, new ZapHtmlLabel(message));
                        getFieldFile().requestFocusInWindow();
                    });
            return false;
        }

        if (result.getCount() == 0) {
            Stats.incCounter(STATS_PREFIX + "import.nomessages");
            ThreadUtils.invokeAndWaitHandled(
                    () -> {
                        showWarningDialog(
                                Constant.messages.getString(
                                        "sequence.importhar.import.nomessages"));
                        getFieldFile().requestFocusInWindow();
                    });
            return false;
        }

        try {
            zest.createScript(sequenceName, scriptType, messages, createScriptOptions());
            Stats.incCounter(STATS_PREFIX + "import");
            Stats.incCounter(STATS_PREFIX + "import.messages", result.getCount());
            return true;
        } catch (Exception e) {
            Stats.incCounter(STATS_PREFIX + "import.script.error");
            ThreadUtils.invokeAndWaitHandled(
                    () -> {
                        showWarningDialog(
                                Constant.messages.getString(
                                        "sequence.importhar.script.error", e.getMessage()));
                        getFieldFile().requestFocusInWindow();
                    });
            return false;
        }
    }

    private CreateScriptOptions createScriptOptions() {
        CreateScriptOptions.Builder builder =
                CreateScriptOptions.builder()
                        .setIncludeResponses(CreateScriptOptions.IncludeResponses.ALWAYS)
                        .setAddStatusAssertion(getFieldAssertCode().isSelected());
        Integer assertLengthValue = box(getFieldAssertLength().getText());
        if (assertLengthValue != null) {
            builder.setAddLengthAssertion(true).setLengthApprox(assertLengthValue);
        }
        return builder.build();
    }

    private static Integer box(String value) {
        if (value.isEmpty()) {
            return null;
        }
        return Integer.valueOf(value);
    }

    private static class IntFilter extends DocumentFilter {

        @Override
        public void insertString(FilterBypass fb, int offset, String string, AttributeSet attr)
                throws BadLocationException {
            String filteredString = stripNonIntChars(string);
            if (filteredString.isEmpty()) {
                return;
            }
            super.insertString(fb, offset, filteredString, attr);
        }

        private static String stripNonIntChars(String str) {
            return str.replaceAll("[^\\d]", "");
        }

        @Override
        public void replace(
                FilterBypass fb, int offset, int length, String text, AttributeSet attrs)
                throws BadLocationException {
            String filteredText = stripNonIntChars(text);
            if (filteredText.isEmpty()) {
                return;
            }
            super.replace(fb, offset, length, filteredText, attrs);
        }
    }

    private static String wrapEntriesInLiTags(List<String> entries) {
        if (entries.isEmpty()) {
            return "";
        }

        StringBuilder strBuilder = new StringBuilder(entries.size() * 15);
        for (String entry : entries) {
            strBuilder.append("<li>");
            strBuilder.append(entry);
            strBuilder.append("</li>");
        }
        return strBuilder.toString();
    }
}
