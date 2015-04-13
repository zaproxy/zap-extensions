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

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
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
import javax.swing.JTextField;
import javax.swing.filechooser.FileFilter;

import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.fuzz.payloads.StringPayload;
import org.zaproxy.zap.extension.fuzz.payloads.generator.FileStringPayloadGenerator;
import org.zaproxy.zap.extension.fuzz.payloads.ui.PayloadGeneratorUI;
import org.zaproxy.zap.extension.fuzz.payloads.ui.PayloadGeneratorUIHandler;
import org.zaproxy.zap.extension.fuzz.payloads.ui.PayloadGeneratorUIPanel;
import org.zaproxy.zap.extension.fuzz.payloads.ui.impl.FileStringPayloadGeneratorUIHandler.FileStringPayloadGeneratorUI;
import org.zaproxy.zap.model.MessageLocation;
import org.zaproxy.zap.utils.ZapNumberSpinner;
import org.zaproxy.zap.utils.ZapTextField;

public class FileStringPayloadGeneratorUIHandler implements
        PayloadGeneratorUIHandler<String, StringPayload, FileStringPayloadGenerator, FileStringPayloadGeneratorUI> {

    private static final String PAYLOAD_GENERATOR_NAME = Constant.messages.getString("fuzz.payloads.generator.file.name");

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

    public static class FileStringPayloadGeneratorUI implements
            PayloadGeneratorUI<String, StringPayload, FileStringPayloadGenerator> {

        private final Path file;
        private final Charset charset;
        private final long limit;
        private final String commentToken;
        private final boolean ignoreTrimmedEmptyLines;
        private final boolean ignoreFirstLine;
        private long numberOfPayloads;

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

    public static class FileStringPayloadGeneratorUIPanel implements
            PayloadGeneratorUIPanel<String, StringPayload, FileStringPayloadGenerator, FileStringPayloadGeneratorUI> {

        private static final Charset[] CHARSETS = {
                StandardCharsets.UTF_8,
                StandardCharsets.ISO_8859_1,
                StandardCharsets.US_ASCII };

        private static final int DEFAULT_LIMIT_NUMBER = 1000;

        private static final String FILE_FIELD_LABEL = Constant.messages.getString("fuzz.payloads.generator.file.file.label");
        private static final String FILE_CHOOSER_BUTTON_LABEL = Constant.messages.getString("fuzz.payloads.generator.file.file.button");
        private static final String FILE_DESCRIPTION = Constant.messages.getString("fuzz.payloads.generator.file.file.description");
        private static final String CHARSET_FIELD_LABEL = Constant.messages.getString("fuzz.payloads.generator.file.charset.label");
        private static final String LIMIT_FIELD_LABEL = Constant.messages.getString("fuzz.payloads.generator.file.limit.label");
        private static final String LIMIT_FIELD_TOOPTIP = Constant.messages.getString("fuzz.payloads.generator.file.limit.tooltip");
        private static final String LIMIT_VALUE_FIELD_LABEL = Constant.messages.getString("fuzz.payloads.generator.file.limit.value.label");
        private static final String LIMIT_NUMBER_FIELD_TOOPTIP = Constant.messages.getString("fuzz.payloads.generator.file.limit.value.tooltip");
        private static final String COMMENT_TOKEN_FIELD_LABEL = Constant.messages.getString("fuzz.payloads.generator.file.commentToken.label");
        private static final String IGNORE_EMPTY_LINES_FIELD_LABEL = Constant.messages.getString("fuzz.payloads.generator.file.ignoreEmptyLines.label");
        private static final String IGNORE_EMPTY_LINES_FIELD_TOOL_TIP = Constant.messages.getString("fuzz.payloads.generator.file.ignoreEmptyLines.tooltip");
        private static final String IGNORE_FIRST_LINE_FIELD_LABEL = Constant.messages.getString("fuzz.payloads.generator.file.ignoreFirstLine.label");

        private JPanel fieldsPanel;

        private JTextField fileTextField;
        private JButton fileChooserButton;
        private JComboBox<Charset> charsetComboBox;
        private JCheckBox limitCheckBox;
        private ZapNumberSpinner limitNumberSpinner;
        private ZapTextField commentTokenTextField;
        private JCheckBox ignoreEmptyLinesCheckBox;
        private JCheckBox ignoreFirstLineCheckBox;

        private long numberOfPayloads;

        private Path lastSelectedDirectory;

        public FileStringPayloadGeneratorUIPanel() {
            fieldsPanel = new JPanel();

            GroupLayout layout = new GroupLayout(fieldsPanel);
            fieldsPanel.setLayout(layout);
            layout.setAutoCreateGaps(true);

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

            layout.setHorizontalGroup(layout.createSequentialGroup()
                    .addGroup(
                            layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                                    .addComponent(fileLabel)
                                    .addComponent(charsetLabel)
                                    .addComponent(limitLabel)
                                    .addComponent(limitValueLabel)
                                    .addComponent(commentTokenLabel)
                                    .addComponent(ignoreEmptyLinesLabel)
                                    .addComponent(ignoreFirstLineLabel))
                    .addGroup(
                            layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                    .addGroup(
                                            layout.createSequentialGroup()
                                                    .addComponent(getFileTextField())
                                                    .addComponent(getFileButton()))
                                    .addComponent(getCharsetComboBox())
                                    .addComponent(getLimitCheckBox())
                                    .addComponent(getLimitNumberSpinner())
                                    .addComponent(getCommentTokenTextField())
                                    .addComponent(getIgnoreEmptyLinesCheckBox())
                                    .addComponent(getIgnoreFirstLineCheckBox())));

            layout.setVerticalGroup(layout.createSequentialGroup()
                    .addGroup(
                            layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                    .addComponent(fileLabel)
                                    .addComponent(getFileTextField())
                                    .addComponent(getFileButton()))
                    .addGroup(
                            layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                    .addComponent(charsetLabel)
                                    .addComponent(getCharsetComboBox()))
                    .addGroup(
                            layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                    .addComponent(limitLabel)
                                    .addComponent(getLimitCheckBox()))
                    .addGroup(
                            layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                    .addComponent(limitValueLabel)
                                    .addComponent(getLimitNumberSpinner()))
                    .addGroup(
                            layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                    .addComponent(commentTokenLabel)
                                    .addComponent(getCommentTokenTextField()))
                    .addGroup(
                            layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                    .addComponent(ignoreEmptyLinesLabel)
                                    .addComponent(getIgnoreEmptyLinesCheckBox()))
                    .addGroup(
                            layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                    .addComponent(ignoreFirstLineLabel)
                                    .addComponent(getIgnoreFirstLineCheckBox())));
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
                fileChooserButton.addActionListener(new ActionListener() {

                    @Override
                    public void actionPerformed(ActionEvent e) {
                        JFileChooser fileChooser = new JFileChooser();
                        fileChooser.setFileFilter(new FileFilter() {

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
                        }

                    }
                });
            }
            return fileChooserButton;
        }

        private JComboBox<Charset> getCharsetComboBox() {
            if (charsetComboBox == null) {
                charsetComboBox = new JComboBox<>(new DefaultComboBoxModel<>(CHARSETS));
            }
            return charsetComboBox;
        }

        private JCheckBox getLimitCheckBox() {
            if (limitCheckBox == null) {
                limitCheckBox = new JCheckBox();
                limitCheckBox.setToolTipText(LIMIT_FIELD_TOOPTIP);
                limitCheckBox.addItemListener(new ItemListener() {

                    @Override
                    public void itemStateChanged(ItemEvent e) {
                        getLimitNumberSpinner().setEnabled(ItemEvent.SELECTED == e.getStateChange());
                    }
                });
            }
            return limitCheckBox;
        }

        private ZapNumberSpinner getLimitNumberSpinner() {
            if (limitNumberSpinner == null) {
                limitNumberSpinner = new ZapNumberSpinner(0, DEFAULT_LIMIT_NUMBER, Integer.MAX_VALUE);
                limitNumberSpinner.setToolTipText(LIMIT_NUMBER_FIELD_TOOPTIP);
                limitNumberSpinner.setEnabled(false);
            }
            return limitNumberSpinner;
        }

        private ZapTextField getCommentTokenTextField() {
            if (commentTokenTextField == null) {
                commentTokenTextField = new ZapTextField(FileStringPayloadGenerator.DEFAULT_COMMENT_TOKEN);
                commentTokenTextField.setColumns(25);
            }
            return commentTokenTextField;
        }

        private JCheckBox getIgnoreEmptyLinesCheckBox() {
            if (ignoreEmptyLinesCheckBox == null) {
                ignoreEmptyLinesCheckBox = new JCheckBox();
                ignoreEmptyLinesCheckBox.setToolTipText(IGNORE_EMPTY_LINES_FIELD_TOOL_TIP);
            }
            return ignoreEmptyLinesCheckBox;
        }

        private JCheckBox getIgnoreFirstLineCheckBox() {
            if (ignoreFirstLineCheckBox == null) {
                ignoreFirstLineCheckBox = new JCheckBox();
            }
            return ignoreFirstLineCheckBox;
        }

        @Override
        public void init(MessageLocation messageLocation) {
        }

        @Override
        public JPanel getComponent() {
            return fieldsPanel;
        }

        @Override
        public void setPayloadGeneratorUI(FileStringPayloadGeneratorUI payloadGeneratorUI) {
            getFileTextField().setText(payloadGeneratorUI.getFile().toString());
            getCharsetComboBox().setSelectedItem(payloadGeneratorUI.getCharset());
            getLimitCheckBox().setSelected(payloadGeneratorUI.getLimit() >= 0);
            getLimitNumberSpinner().setValue((int) payloadGeneratorUI.getLimit());
            getCommentTokenTextField().setText(payloadGeneratorUI.getCommentToken());
            getIgnoreEmptyLinesCheckBox().setSelected(payloadGeneratorUI.isIgnoreEmptyLines());
            numberOfPayloads = payloadGeneratorUI.getNumberOfPayloads();
        }

        @Override
        public FileStringPayloadGeneratorUI getPayloadGeneratorUI() {
            return new FileStringPayloadGeneratorUI(
                    Paths.get(getFileTextField().getText()),
                    (Charset) getCharsetComboBox().getSelectedItem(),
                    getLimitCheckBox().isSelected() ? getLimitNumberSpinner().getValue().intValue() : -1,
                    getCommentTokenTextField().getText(),
                    getIgnoreEmptyLinesCheckBox().isSelected(),
                    getIgnoreFirstLineCheckBox().isSelected(),
                    numberOfPayloads);
        }

        @Override
        public void clear() {
            getFileTextField().setText("");
            getCharsetComboBox().setSelectedIndex(0);
            getLimitCheckBox().setSelected(false);
            getLimitNumberSpinner().setValue(DEFAULT_LIMIT_NUMBER);
            getCommentTokenTextField().setText(FileStringPayloadGenerator.DEFAULT_COMMENT_TOKEN);
            getCommentTokenTextField().discardAllEdits();
            getIgnoreEmptyLinesCheckBox().setSelected(false);
            numberOfPayloads = 0;
        }

        @Override
        public boolean validate() {
            if (getFileTextField().getText().isEmpty()) {
                JOptionPane.showMessageDialog(
                        null,
                        Constant.messages.getString("fuzz.payloads.generator.file.warnNoFile.message"),
                        Constant.messages.getString("fuzz.payloads.generator.file.warnNoFile.title"),
                        JOptionPane.INFORMATION_MESSAGE);
                getFileTextField().requestFocusInWindow();
                return false;
            }

            try {
                numberOfPayloads = FileStringPayloadGenerator.calculateNumberOfPayloads(
                        Paths.get(getFileTextField().getText()),
                        (Charset) getCharsetComboBox().getSelectedItem(),
                        getLimitCheckBox().isSelected() ? getLimitNumberSpinner().getValue().intValue() : -1,
                        getCommentTokenTextField().getText(),
                        getIgnoreEmptyLinesCheckBox().isSelected(),
                        getIgnoreFirstLineCheckBox().isSelected());
            } catch (IOException e) {
                JOptionPane.showMessageDialog(
                        null,
                        Constant.messages.getString("fuzz.payloads.generator.file.warnErrorReadingFile.message"),
                        Constant.messages.getString("fuzz.payloads.generator.file.warnErrorReadingFile.title"),
                        JOptionPane.INFORMATION_MESSAGE);
            }

            return true;
        }

        @Override
        public String getHelpTarget() {
            // THC add help page...
            return null;
        }
    }
}
