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
package org.zaproxy.zap.extension.fuzz.payloads.ui.impl;

import java.awt.event.ItemEvent;
import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import javax.swing.DefaultComboBoxModel;
import javax.swing.GroupLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.filechooser.FileFilter;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.fuzz.payloads.DefaultPayload;
import org.zaproxy.zap.extension.fuzz.payloads.generator.FileStringPayloadGenerator;
import org.zaproxy.zap.extension.fuzz.payloads.ui.PayloadGeneratorUI;
import org.zaproxy.zap.extension.fuzz.payloads.ui.PayloadGeneratorUIHandler;
import org.zaproxy.zap.extension.fuzz.payloads.ui.impl.FileStringPayloadGeneratorUIHandler.FileStringPayloadGeneratorUI;
import org.zaproxy.zap.model.MessageLocation;
import org.zaproxy.zap.utils.FontUtils;
import org.zaproxy.zap.utils.ResettableAutoCloseableIterator;
import org.zaproxy.zap.utils.ZapNumberSpinner;
import org.zaproxy.zap.utils.ZapTextField;

public class FileStringPayloadGeneratorUIHandler
        implements PayloadGeneratorUIHandler<
                DefaultPayload, FileStringPayloadGenerator, FileStringPayloadGeneratorUI> {

    private static final String PAYLOAD_GENERATOR_NAME =
            Constant.messages.getString("fuzz.payloads.generator.file.name");

    @Override
    public String getName() {
        return PAYLOAD_GENERATOR_NAME;
    }

    @Override
    public Class<FileStringPayloadGeneratorUI> getPayloadGeneratorUIClass() {
        return FileStringPayloadGeneratorUI.class;
    }

    @Override
    public Class<FileStringPayloadGeneratorUIPanel> getPayloadGeneratorUIPanelClass() {
        return FileStringPayloadGeneratorUIPanel.class;
    }

    @Override
    public FileStringPayloadGeneratorUIPanel createPanel() {
        return new FileStringPayloadGeneratorUIPanel();
    }

    public static class FileStringPayloadGeneratorUI
            implements PayloadGeneratorUI<DefaultPayload, FileStringPayloadGenerator> {

        private final Path file;
        private final Charset charset;
        private final long limit;
        private final String commentToken;
        private final boolean ignoreTrimmedEmptyLines;
        private final boolean ignoreFirstLine;
        private long numberOfPayloads;

        private boolean temporary;
        private String fileName;

        public FileStringPayloadGeneratorUI(String fileName, Path file, long numberOfPayloads) {
            this(file, StandardCharsets.UTF_8, -1, "", false, false, numberOfPayloads);
            this.temporary = true;
            this.fileName = fileName;
        }

        public FileStringPayloadGeneratorUI(
                Path file,
                Charset charset,
                long limit,
                String commentToken,
                boolean ignoreTrimmedEmptyLines,
                boolean ignoreFirstLine,
                long numberOfPayloads) {
            this.file = file;
            this.charset = charset;
            this.limit = limit;
            this.commentToken = commentToken;
            this.ignoreTrimmedEmptyLines = ignoreTrimmedEmptyLines;
            this.ignoreFirstLine = ignoreFirstLine;
            this.numberOfPayloads = numberOfPayloads;
        }

        public Path getFile() {
            return file;
        }

        public Charset getCharset() {
            return charset;
        }

        public long getLimit() {
            return limit;
        }

        public String getCommentToken() {
            return commentToken;
        }

        public boolean isIgnoreEmptyLines() {
            return ignoreTrimmedEmptyLines;
        }

        public boolean isIgnoreFirstLine() {
            return ignoreFirstLine;
        }

        public boolean isTemporary() {
            return temporary;
        }

        @Override
        public Class<FileStringPayloadGenerator> getPayloadGeneratorClass() {
            return FileStringPayloadGenerator.class;
        }

        @Override
        public String getName() {
            return PAYLOAD_GENERATOR_NAME;
        }

        @Override
        public String getDescription() {
            if (temporary) {
                return fileName;
            }
            return file.getFileName().toString();
        }

        @Override
        public long getNumberOfPayloads() {
            return numberOfPayloads;
        }

        @Override
        public FileStringPayloadGenerator getPayloadGenerator() {
            return new FileStringPayloadGenerator(
                    file,
                    charset,
                    limit,
                    commentToken,
                    ignoreTrimmedEmptyLines,
                    ignoreFirstLine,
                    numberOfPayloads);
        }

        @Override
        public FileStringPayloadGeneratorUI copy() {
            return this;
        }
    }

    public static class FileStringPayloadGeneratorUIPanel
            extends AbstractPersistentPayloadGeneratorUIPanel<
                    DefaultPayload, FileStringPayloadGenerator, FileStringPayloadGeneratorUI> {

        private static final Charset[] CHARSETS = {
            StandardCharsets.UTF_8, StandardCharsets.ISO_8859_1, StandardCharsets.US_ASCII
        };

        private static final int DEFAULT_LIMIT_NUMBER = 1000;

        private static final int MAX_NUMBER_PAYLOADS_PREVIEW = 500;

        private static final String FILE_FIELD_LABEL =
                Constant.messages.getString("fuzz.payloads.generator.file.file.label");
        private static final String FILE_CHOOSER_BUTTON_LABEL =
                Constant.messages.getString("fuzz.payloads.generator.file.file.button");
        private static final String FILE_DESCRIPTION =
                Constant.messages.getString("fuzz.payloads.generator.file.file.description");
        private static final String CHARSET_FIELD_LABEL =
                Constant.messages.getString("fuzz.payloads.generator.file.charset.label");
        private static final String LIMIT_FIELD_LABEL =
                Constant.messages.getString("fuzz.payloads.generator.file.limit.label");
        private static final String LIMIT_FIELD_TOOPTIP =
                Constant.messages.getString("fuzz.payloads.generator.file.limit.tooltip");
        private static final String LIMIT_VALUE_FIELD_LABEL =
                Constant.messages.getString("fuzz.payloads.generator.file.limit.value.label");
        private static final String LIMIT_NUMBER_FIELD_TOOPTIP =
                Constant.messages.getString("fuzz.payloads.generator.file.limit.value.tooltip");
        private static final String COMMENT_TOKEN_FIELD_LABEL =
                Constant.messages.getString("fuzz.payloads.generator.file.commentToken.label");
        private static final String IGNORE_EMPTY_LINES_FIELD_LABEL =
                Constant.messages.getString("fuzz.payloads.generator.file.ignoreEmptyLines.label");
        private static final String IGNORE_EMPTY_LINES_FIELD_TOOL_TIP =
                Constant.messages.getString(
                        "fuzz.payloads.generator.file.ignoreEmptyLines.tooltip");
        private static final String IGNORE_FIRST_LINE_FIELD_LABEL =
                Constant.messages.getString("fuzz.payloads.generator.file.ignoreFirstLine.label");
        private static final String PAYLOADS_PREVIEW_FIELD_LABEL =
                Constant.messages.getString("fuzz.payloads.generator.file.payloadsPreview.label");

        private JPanel fieldsPanel;
        private GroupLayout mainLayout;

        private JPanel addPanel;
        private ModifyFileStringPayloadsPanel modifyPanel;

        private JTextField fileTextField;
        private JButton fileChooserButton;
        private JComboBox<Charset> charsetComboBox;
        private JCheckBox limitCheckBox;
        private ZapNumberSpinner limitNumberSpinner;
        private ZapTextField commentTokenTextField;
        private JCheckBox ignoreEmptyLinesCheckBox;
        private JCheckBox ignoreFirstLineCheckBox;
        private JTextArea payloadsPreviewTextArea;

        private long numberOfPayloads;

        private Path lastSelectedDirectory;

        private boolean modifyFileContents;

        public FileStringPayloadGeneratorUIPanel() {
            addPanel = new JPanel();

            GroupLayout layoutAddPanel = new GroupLayout(addPanel);
            addPanel.setLayout(layoutAddPanel);
            layoutAddPanel.setAutoCreateGaps(true);

            JLabel fileLabel = new JLabel(FILE_FIELD_LABEL);
            fileLabel.setLabelFor(getFileButton());
            JLabel charsetLabel = new JLabel(CHARSET_FIELD_LABEL);
            charsetLabel.setLabelFor(getCharsetComboBox());
            JLabel limitLabel = new JLabel(LIMIT_FIELD_LABEL);
            limitLabel.setLabelFor(getLimitCheckBox());
            JLabel limitValueLabel = new JLabel(LIMIT_VALUE_FIELD_LABEL);
            limitValueLabel.setLabelFor(getLimitNumberSpinner());
            JLabel commentTokenLabel = new JLabel(COMMENT_TOKEN_FIELD_LABEL);
            commentTokenLabel.setLabelFor(getCommentTokenTextField());
            JLabel ignoreEmptyLinesLabel = new JLabel(IGNORE_EMPTY_LINES_FIELD_LABEL);
            ignoreEmptyLinesLabel.setLabelFor(getIgnoreEmptyLinesCheckBox());
            JLabel ignoreFirstLineLabel = new JLabel(IGNORE_FIRST_LINE_FIELD_LABEL);
            ignoreFirstLineLabel.setLabelFor(getIgnoreFirstLineCheckBox());
            JLabel payloadsPreviewLabel = new JLabel(PAYLOADS_PREVIEW_FIELD_LABEL);
            payloadsPreviewLabel.setLabelFor(getPayloadsPreviewTextArea());

            JScrollPane payloadsPreviewScrollPane = new JScrollPane(getPayloadsPreviewTextArea());

            layoutAddPanel.setHorizontalGroup(
                    layoutAddPanel
                            .createSequentialGroup()
                            .addGroup(
                                    layoutAddPanel
                                            .createParallelGroup(GroupLayout.Alignment.TRAILING)
                                            .addComponent(fileLabel)
                                            .addComponent(charsetLabel)
                                            .addComponent(limitLabel)
                                            .addComponent(limitValueLabel)
                                            .addComponent(commentTokenLabel)
                                            .addComponent(ignoreEmptyLinesLabel)
                                            .addComponent(ignoreFirstLineLabel)
                                            .addComponent(payloadsPreviewLabel))
                            .addGroup(
                                    layoutAddPanel
                                            .createParallelGroup(GroupLayout.Alignment.LEADING)
                                            .addGroup(
                                                    layoutAddPanel
                                                            .createSequentialGroup()
                                                            .addComponent(getFileTextField())
                                                            .addComponent(getFileButton()))
                                            .addComponent(getCharsetComboBox())
                                            .addComponent(getLimitCheckBox())
                                            .addComponent(getLimitNumberSpinner())
                                            .addComponent(getCommentTokenTextField())
                                            .addComponent(getIgnoreEmptyLinesCheckBox())
                                            .addComponent(getIgnoreFirstLineCheckBox())
                                            .addComponent(payloadsPreviewScrollPane)
                                            .addComponent(getSaveButton())));

            layoutAddPanel.setVerticalGroup(
                    layoutAddPanel
                            .createSequentialGroup()
                            .addGroup(
                                    layoutAddPanel
                                            .createParallelGroup(GroupLayout.Alignment.BASELINE)
                                            .addComponent(fileLabel)
                                            .addComponent(getFileTextField())
                                            .addComponent(getFileButton()))
                            .addGroup(
                                    layoutAddPanel
                                            .createParallelGroup(GroupLayout.Alignment.BASELINE)
                                            .addComponent(charsetLabel)
                                            .addComponent(getCharsetComboBox()))
                            .addGroup(
                                    layoutAddPanel
                                            .createParallelGroup(GroupLayout.Alignment.BASELINE)
                                            .addComponent(limitLabel)
                                            .addComponent(getLimitCheckBox()))
                            .addGroup(
                                    layoutAddPanel
                                            .createParallelGroup(GroupLayout.Alignment.BASELINE)
                                            .addComponent(limitValueLabel)
                                            .addComponent(getLimitNumberSpinner()))
                            .addGroup(
                                    layoutAddPanel
                                            .createParallelGroup(GroupLayout.Alignment.BASELINE)
                                            .addComponent(commentTokenLabel)
                                            .addComponent(getCommentTokenTextField()))
                            .addGroup(
                                    layoutAddPanel
                                            .createParallelGroup(GroupLayout.Alignment.BASELINE)
                                            .addComponent(ignoreEmptyLinesLabel)
                                            .addComponent(getIgnoreEmptyLinesCheckBox()))
                            .addGroup(
                                    layoutAddPanel
                                            .createParallelGroup(GroupLayout.Alignment.BASELINE)
                                            .addComponent(ignoreFirstLineLabel)
                                            .addComponent(getIgnoreFirstLineCheckBox()))
                            .addGroup(
                                    layoutAddPanel
                                            .createParallelGroup(GroupLayout.Alignment.BASELINE)
                                            .addComponent(payloadsPreviewLabel)
                                            .addComponent(payloadsPreviewScrollPane))
                            .addComponent(getSaveButton()));

            fieldsPanel = new JPanel();
            mainLayout = new GroupLayout(fieldsPanel);
            fieldsPanel.setLayout(mainLayout);

            mainLayout.setHorizontalGroup(
                    mainLayout.createSequentialGroup().addComponent(addPanel));
            mainLayout.setVerticalGroup(mainLayout.createSequentialGroup().addComponent(addPanel));
        }

        private ModifyFileStringPayloadsPanel getModifyPanel() {
            if (modifyPanel == null) {
                modifyPanel = new ModifyFileStringPayloadsPanel(createSaveButton());
            }
            return modifyPanel;
        }

        private JTextField getFileTextField() {
            if (fileTextField == null) {
                fileTextField = new JTextField();
                fileTextField.setEditable(false);
                fileTextField.setColumns(25);
            }
            return fileTextField;
        }

        private JButton getFileButton() {
            if (fileChooserButton == null) {
                fileChooserButton = new JButton(FILE_CHOOSER_BUTTON_LABEL);
                fileChooserButton.addActionListener(
                        e -> {
                            JFileChooser fileChooser = new JFileChooser();
                            fileChooser.setFileFilter(
                                    new FileFilter() {

                                        @Override
                                        public String getDescription() {
                                            return FILE_DESCRIPTION;
                                        }

                                        @Override
                                        public boolean accept(File f) {
                                            return f.isDirectory() || f.canRead();
                                        }
                                    });

                            boolean pathSet = false;
                            String path = getFileTextField().getText();
                            if (!path.isEmpty()) {
                                File file = new File(path);
                                if (file.exists()) {
                                    fileChooser.setSelectedFile(file);
                                    pathSet = true;
                                }
                            }

                            if (!pathSet && lastSelectedDirectory != null) {
                                fileChooser.setCurrentDirectory(lastSelectedDirectory.toFile());
                            }

                            if (fileChooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
                                final File selectedFile = fileChooser.getSelectedFile();
                                lastSelectedDirectory = selectedFile.toPath().getParent();

                                getFileTextField().setText(selectedFile.getAbsolutePath());
                                getSaveButton().setEnabled(true);
                                updatePayloadsPreviewTextArea();
                            }
                        });
            }
            return fileChooserButton;
        }

        private void updatePayloadsPreviewTextArea() {
            StringBuilder contents = new StringBuilder(MAX_NUMBER_PAYLOADS_PREVIEW * 25);
            if (!getFileTextField().getText().isEmpty()) {
                try {
                    int numberOfPayloads =
                            FileStringPayloadGenerator.calculateNumberOfPayloads(
                                    Paths.get(getFileTextField().getText()),
                                    (Charset) getCharsetComboBox().getSelectedItem(),
                                    MAX_NUMBER_PAYLOADS_PREVIEW,
                                    getCommentTokenTextField().getText(),
                                    getIgnoreEmptyLinesCheckBox().isSelected(),
                                    getIgnoreFirstLineCheckBox().isSelected());

                    FileStringPayloadGenerator payloadGenerator =
                            new FileStringPayloadGenerator(
                                    Paths.get(getFileTextField().getText()),
                                    (Charset) getCharsetComboBox().getSelectedItem(),
                                    MAX_NUMBER_PAYLOADS_PREVIEW,
                                    getCommentTokenTextField().getText(),
                                    getIgnoreEmptyLinesCheckBox().isSelected(),
                                    getIgnoreFirstLineCheckBox().isSelected(),
                                    numberOfPayloads);
                    try (ResettableAutoCloseableIterator<DefaultPayload> payloads =
                            payloadGenerator.iterator()) {
                        for (int i = 0;
                                i < MAX_NUMBER_PAYLOADS_PREVIEW && payloads.hasNext();
                                i++) {
                            if (contents.length() > 0) {
                                contents.append('\n');
                            }
                            contents.append(payloads.next().getValue());
                        }
                    }
                    getPayloadsPreviewTextArea().setEnabled(true);
                } catch (Exception ignore) {
                    contents.setLength(0);
                    contents.append(
                            Constant.messages.getString(
                                    "fuzz.payloads.generator.file.payloadsPreview.error"));
                    getPayloadsPreviewTextArea().setEnabled(false);
                }
            }
            getPayloadsPreviewTextArea().setText(contents.toString());
            getPayloadsPreviewTextArea().setCaretPosition(0);
        }

        private JComboBox<Charset> getCharsetComboBox() {
            if (charsetComboBox == null) {
                charsetComboBox = new JComboBox<>(new DefaultComboBoxModel<>(CHARSETS));
                charsetComboBox.addItemListener(e -> updatePayloadsPreviewTextArea());
            }
            return charsetComboBox;
        }

        private JCheckBox getLimitCheckBox() {
            if (limitCheckBox == null) {
                limitCheckBox = new JCheckBox();
                limitCheckBox.setToolTipText(LIMIT_FIELD_TOOPTIP);
                limitCheckBox.addItemListener(
                        e ->
                                getLimitNumberSpinner()
                                        .setEnabled(ItemEvent.SELECTED == e.getStateChange()));
            }
            return limitCheckBox;
        }

        private ZapNumberSpinner getLimitNumberSpinner() {
            if (limitNumberSpinner == null) {
                limitNumberSpinner =
                        new ZapNumberSpinner(0, DEFAULT_LIMIT_NUMBER, Integer.MAX_VALUE);
                limitNumberSpinner.setToolTipText(LIMIT_NUMBER_FIELD_TOOPTIP);
                limitNumberSpinner.setEnabled(false);
            }
            return limitNumberSpinner;
        }

        private ZapTextField getCommentTokenTextField() {
            if (commentTokenTextField == null) {
                commentTokenTextField =
                        new ZapTextField(FileStringPayloadGenerator.DEFAULT_COMMENT_TOKEN);
                commentTokenTextField.setColumns(25);
                commentTokenTextField
                        .getDocument()
                        .addDocumentListener(
                                new DocumentListener() {

                                    @Override
                                    public void removeUpdate(DocumentEvent e) {
                                        update();
                                    }

                                    @Override
                                    public void insertUpdate(DocumentEvent e) {
                                        update();
                                    }

                                    @Override
                                    public void changedUpdate(DocumentEvent e) {
                                        update();
                                    }

                                    private void update() {
                                        updatePayloadsPreviewTextArea();
                                    }
                                });
            }
            return commentTokenTextField;
        }

        private JCheckBox getIgnoreEmptyLinesCheckBox() {
            if (ignoreEmptyLinesCheckBox == null) {
                ignoreEmptyLinesCheckBox = new JCheckBox();
                ignoreEmptyLinesCheckBox.setToolTipText(IGNORE_EMPTY_LINES_FIELD_TOOL_TIP);
                ignoreEmptyLinesCheckBox.addItemListener(e -> updatePayloadsPreviewTextArea());
            }
            return ignoreEmptyLinesCheckBox;
        }

        private JCheckBox getIgnoreFirstLineCheckBox() {
            if (ignoreFirstLineCheckBox == null) {
                ignoreFirstLineCheckBox = new JCheckBox();
                ignoreFirstLineCheckBox.addItemListener(e -> updatePayloadsPreviewTextArea());
            }
            return ignoreFirstLineCheckBox;
        }

        private JTextArea getPayloadsPreviewTextArea() {
            if (payloadsPreviewTextArea == null) {
                payloadsPreviewTextArea = new JTextArea(5, 10);
                payloadsPreviewTextArea.setEditable(false);
                payloadsPreviewTextArea.setFont(FontUtils.getFont("Monospaced"));
            }
            return payloadsPreviewTextArea;
        }

        @Override
        public void init(MessageLocation messageLocation) {
            modifyFileContents = false;
        }

        @Override
        public JPanel getComponent() {
            return fieldsPanel;
        }

        @Override
        public void setPayloadGeneratorUI(FileStringPayloadGeneratorUI payloadGeneratorUI) {
            modifyFileContents = true;
            mainLayout.replace(addPanel, getModifyPanel().getPanel());

            getModifyPanel()
                    .setPayloadGeneratorUI(
                            payloadGeneratorUI,
                            !payloadGeneratorUI.isTemporary(),
                            payloadGeneratorUI.getFile());
        }

        @Override
        public FileStringPayloadGeneratorUI getPayloadGeneratorUI() {
            if (modifyFileContents) {
                return getModifyPanel().getFileStringPayloadGeneratorUI();
            }
            return new FileStringPayloadGeneratorUI(
                    Paths.get(getFileTextField().getText()),
                    (Charset) getCharsetComboBox().getSelectedItem(),
                    getLimitCheckBox().isSelected()
                            ? getLimitNumberSpinner().getValue().intValue()
                            : -1,
                    getCommentTokenTextField().getText(),
                    getIgnoreEmptyLinesCheckBox().isSelected(),
                    getIgnoreFirstLineCheckBox().isSelected(),
                    numberOfPayloads);
        }

        @Override
        protected FileStringPayloadGenerator getPayloadGenerator() {
            if (modifyFileContents) {
                if (getModifyPanel().isValidForPersistence()) {
                    return getModifyPanel().getPayloadGenerator();
                }
                return null;
            }
            if (!validate()) {
                return null;
            }
            return new FileStringPayloadGenerator(
                    Paths.get(getFileTextField().getText()),
                    (Charset) getCharsetComboBox().getSelectedItem(),
                    getLimitCheckBox().isSelected()
                            ? getLimitNumberSpinner().getValue().intValue()
                            : -1,
                    getCommentTokenTextField().getText(),
                    getIgnoreEmptyLinesCheckBox().isSelected(),
                    getIgnoreFirstLineCheckBox().isSelected(),
                    numberOfPayloads);
        }

        @Override
        public void clear() {
            if (modifyFileContents) {
                getModifyPanel().clear();
                mainLayout.replace(getModifyPanel().getPanel(), addPanel);
                return;
            }
            getFileTextField().setText("");
            getCharsetComboBox().setSelectedIndex(0);
            getLimitCheckBox().setSelected(false);
            getLimitNumberSpinner().setValue(DEFAULT_LIMIT_NUMBER);
            getCommentTokenTextField().setText(FileStringPayloadGenerator.DEFAULT_COMMENT_TOKEN);
            getCommentTokenTextField().discardAllEdits();
            getIgnoreEmptyLinesCheckBox().setSelected(false);
            numberOfPayloads = 0;
            getPayloadsPreviewTextArea().setText("");
            getSaveButton().setEnabled(false);
        }

        @Override
        public boolean validate() {
            if (modifyFileContents) {
                return getModifyPanel().validate();
            }

            if (getFileTextField().getText().isEmpty()) {
                JOptionPane.showMessageDialog(
                        null,
                        Constant.messages.getString(
                                "fuzz.payloads.generator.file.warnNoFile.message"),
                        Constant.messages.getString(
                                "fuzz.payloads.generator.file.warnNoFile.title"),
                        JOptionPane.INFORMATION_MESSAGE);
                getFileTextField().requestFocusInWindow();
                return false;
            }

            try {
                numberOfPayloads =
                        FileStringPayloadGenerator.calculateNumberOfPayloads(
                                Paths.get(getFileTextField().getText()),
                                (Charset) getCharsetComboBox().getSelectedItem(),
                                getLimitCheckBox().isSelected()
                                        ? getLimitNumberSpinner().getValue().intValue()
                                        : -1,
                                getCommentTokenTextField().getText(),
                                getIgnoreEmptyLinesCheckBox().isSelected(),
                                getIgnoreFirstLineCheckBox().isSelected());
            } catch (IOException e) {
                JOptionPane.showMessageDialog(
                        null,
                        Constant.messages.getString(
                                "fuzz.payloads.generator.file.warnErrorReadingFile.message"),
                        Constant.messages.getString(
                                "fuzz.payloads.generator.file.warnErrorReadingFile.title"),
                        JOptionPane.INFORMATION_MESSAGE);
            }

            return true;
        }

        private static class ModifyFileStringPayloadsPanel
                extends ModifyPayloadsPanel<
                        DefaultPayload, FileStringPayloadGenerator, FileStringPayloadGeneratorUI> {

            public ModifyFileStringPayloadsPanel(JButton saveButton) {
                super(saveButton);
            }

            @Override
            public FileStringPayloadGenerator getPayloadGenerator() {
                return new FileStringPayloadGenerator(getFile(), 1) {

                    @Override
                    public ResettableAutoCloseableIterator<DefaultPayload> iterator() {
                        return new TextAreaPayloadIterator(getPayloadsTextArea());
                    }
                };
            }

            @Override
            protected FileStringPayloadGeneratorUI createPayloadGeneratorUI(int numberOfPayloads) {
                return new FileStringPayloadGeneratorUI(
                        getPayloadGeneratorUI().getDescription(), getFile(), numberOfPayloads);
            }
        }
    }
}
