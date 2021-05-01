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

import java.awt.Desktop;
import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import javax.swing.GroupLayout;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.text.BadLocationException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.fuzz.payloads.DefaultPayload;
import org.zaproxy.zap.extension.fuzz.payloads.Payload;
import org.zaproxy.zap.extension.fuzz.payloads.generator.FileStringPayloadGenerator;
import org.zaproxy.zap.extension.fuzz.payloads.generator.PayloadGenerator;
import org.zaproxy.zap.extension.fuzz.payloads.ui.PayloadGeneratorUI;
import org.zaproxy.zap.utils.FontUtils;
import org.zaproxy.zap.utils.ResettableAutoCloseableIterator;
import org.zaproxy.zap.utils.ZapTextArea;

public abstract class ModifyPayloadsPanel<
        T extends Payload, T2 extends PayloadGenerator<T>, T3 extends PayloadGeneratorUI<T, T2>> {

    private final Logger logger = LogManager.getLogger(getClass());

    private static final String PAYLOADS_FIELD_LABEL =
            Constant.messages.getString("fuzz.payloads.generator.generic.edit.payloads.label");

    private static final int MAX_NUMBER_PAYLOADS_FOR_EDITION = 250000;
    private static final int MAX_FILE_SIZE_FOR_EDITION = 5 * 1024 * 1024;

    private final JPanel fieldsPanel;

    private ZapTextArea payloadsTextArea;
    private JButton saveButton;

    private Path file;
    private boolean createTempFile;
    private boolean externalEditor;

    private T3 payloadGeneratorUI;

    public ModifyPayloadsPanel(JButton saveButton) {
        this.fieldsPanel = new JPanel();
        this.saveButton = saveButton;
        this.saveButton.setEnabled(false);

        GroupLayout layoutModifyPanel = new GroupLayout(fieldsPanel);
        fieldsPanel.setLayout(layoutModifyPanel);
        layoutModifyPanel.setAutoCreateGaps(true);

        JLabel valueLabel = new JLabel(PAYLOADS_FIELD_LABEL);
        valueLabel.setLabelFor(getPayloadsTextArea());

        JScrollPane payloadsTextAreaScrollPane = new JScrollPane(getPayloadsTextArea());

        layoutModifyPanel.setHorizontalGroup(
                layoutModifyPanel
                        .createSequentialGroup()
                        .addGroup(
                                layoutModifyPanel
                                        .createParallelGroup(GroupLayout.Alignment.TRAILING)
                                        .addComponent(valueLabel))
                        .addGroup(
                                layoutModifyPanel
                                        .createParallelGroup(GroupLayout.Alignment.LEADING)
                                        .addComponent(payloadsTextAreaScrollPane)
                                        .addComponent(saveButton)));

        layoutModifyPanel.setVerticalGroup(
                layoutModifyPanel
                        .createSequentialGroup()
                        .addGroup(
                                layoutModifyPanel
                                        .createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(valueLabel)
                                        .addComponent(payloadsTextAreaScrollPane))
                        .addComponent(saveButton));
    }

    public abstract T2 getPayloadGenerator();

    public T3 getFileStringPayloadGeneratorUI() {
        int numberOfPayloads = 0;
        if (externalEditor) {
            if (createTempFile) {
                return payloadGeneratorUI;
            }

            try {
                numberOfPayloads =
                        FileStringPayloadGenerator.calculateNumberOfPayloads(
                                file, StandardCharsets.UTF_8, -1, "", false, false);
            } catch (IOException e) {
                logger.warn("Failed to calculate number of payloads: {}", e.getMessage());
            }
        } else {
            numberOfPayloads = getPayloadsTextArea().getLineCount();
        }
        return createPayloadGeneratorUI(numberOfPayloads);
    }

    protected abstract T3 createPayloadGeneratorUI(int numberOfPayloads);

    public boolean isValidForPersistence() {
        return saveButton.isEnabled();
    }

    public boolean validate() {
        if (!getPayloadsTextArea().isEnabled()) {
            return true;
        }
        if (createTempFile) {
            if (!createTempFile()) {
                return false;
            }
        }
        persistPayloads();
        return true;
    }

    private void persistPayloads() {
        int numberOfPayloads = getPayloadsTextArea().getLineCount();
        try (BufferedWriter bw =
                Files.newBufferedWriter(
                        file,
                        StandardCharsets.UTF_8,
                        StandardOpenOption.CREATE,
                        StandardOpenOption.TRUNCATE_EXISTING)) {
            for (int i = 0; i < numberOfPayloads; i++) {
                int offset = getPayloadsTextArea().getLineStartOffset(i);
                int length = getPayloadsTextArea().getLineEndOffset(i) - offset;
                bw.write(getPayloadsTextArea().getText(offset, length));
            }
        } catch (Exception e) {
            logger.warn("Failed to write the payloads to the file: {}", e.getMessage());
            View.getSingleton()
                    .showWarningDialog(
                            Constant.messages.getString(
                                    "fuzz.payloads.generator.generic.edit.errorWrite"));
        }
    }

    private boolean createTempFile() {
        try {
            file = Files.createTempFile(null, ".tmp.txt");
            file.toFile().deleteOnExit();
            createTempFile = false;
            return true;
        } catch (IOException e) {
            logger.warn(
                    "Failed to create temporary file to write the payloads: {}", e.getMessage());
            View.getSingleton()
                    .showWarningDialog(
                            Constant.messages.getString(
                                    "fuzz.payloads.generator.generic.edit.errorCreate"));
        }
        return false;
    }

    private boolean writeToFile(T2 payloadGenerator, Path file) {
        try (BufferedWriter bw =
                        Files.newBufferedWriter(
                                file,
                                StandardCharsets.UTF_8,
                                StandardOpenOption.CREATE,
                                StandardOpenOption.TRUNCATE_EXISTING);
                ResettableAutoCloseableIterator<T> it = payloadGenerator.iterator()) {
            while (it.hasNext()) {
                bw.write(it.next().getValue());
                if (it.hasNext()) {
                    bw.write('\n');
                }
            }
        } catch (Exception e) {
            logger.warn("Failed to write the payloads to the file: {}", e.getMessage());
            View.getSingleton()
                    .showWarningDialog(
                            Constant.messages.getString(
                                    "fuzz.payloads.generator.generic.edit.errorWrite"));
            return false;
        }
        return true;
    }

    public JPanel getPanel() {
        return fieldsPanel;
    }

    protected Path getFile() {
        return file;
    }

    protected T3 getPayloadGeneratorUI() {
        return payloadGeneratorUI;
    }

    protected ZapTextArea getPayloadsTextArea() {
        if (payloadsTextArea == null) {
            payloadsTextArea = new ZapTextArea(25, 25);
            payloadsTextArea.setEnabled(false);
            payloadsTextArea.setFont(FontUtils.getFont("Monospaced"));
        }
        return payloadsTextArea;
    }

    public void setPayloadGeneratorUI(T3 payloadGeneratorUI, boolean temporary, Path file) {
        this.payloadGeneratorUI = payloadGeneratorUI;
        createTempFile = temporary;
        this.file = file;

        externalEditor = false;
        if (!canEdit(file)) {
            externalEditor = true;
            openExternalEditor();
            return;
        }

        updatePayloadsTextArea(payloadGeneratorUI.getPayloadGenerator());
    }

    private boolean canEdit(Path file) {
        if (payloadGeneratorUI.getNumberOfPayloads() >= MAX_NUMBER_PAYLOADS_FOR_EDITION) {
            return false;
        }

        if (file == null) {
            return true;
        }

        try {
            return !(Files.size(file) >= MAX_FILE_SIZE_FOR_EDITION);
        } catch (IOException e) {
            logger.warn("Failed to query the size of the file [{}]: {}", file, e.getMessage());
            getPayloadsTextArea()
                    .setText(
                            Constant.messages.getString(
                                    "fuzz.payloads.generator.generic.edit.errorSize"));
        }
        return false;
    }

    private void openExternalEditor() {
        if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.OPEN)) {
            if (JOptionPane.showConfirmDialog(
                            null,
                            Constant.messages.getString(
                                    "fuzz.payloads.generator.generic.edit.external.message"),
                            Constant.messages.getString(
                                    "fuzz.payloads.generator.generic.edit.external.title"),
                            JOptionPane.YES_NO_OPTION)
                    == JOptionPane.YES_OPTION) {
                boolean openFile = false;
                if (!createTempFile) {
                    openFile = true;
                } else {
                    if (createTempFile()) {
                        writeToFile(payloadGeneratorUI.getPayloadGenerator(), file);
                        openFile = true;
                    }
                }

                if (openFile) {
                    try {
                        getPayloadsTextArea()
                                .setText(
                                        Constant.messages.getString(
                                                "fuzz.payloads.generator.generic.edit.external.opening"));
                        Desktop.getDesktop().open(file.toFile());
                        getPayloadsTextArea()
                                .setText(
                                        Constant.messages.getString(
                                                "fuzz.payloads.generator.generic.edit.external.closeDialog"));
                        return;
                    } catch (IOException e) {
                        View.getSingleton()
                                .showWarningDialog(
                                        Constant.messages.getString(
                                                "fuzz.payloads.generator.generic.edit.external.errorFailedOpen"));
                    }
                }
            }
        }
        getPayloadsTextArea()
                .setText(
                        Constant.messages.getString(
                                "fuzz.payloads.generator.generic.edit.warnTooBig"));
    }

    private void updatePayloadsTextArea(T2 fileStringPayloadGenerator) {
        StringBuilder contents = new StringBuilder(2500);
        try {
            try (ResettableAutoCloseableIterator<T> payloads =
                    fileStringPayloadGenerator.iterator()) {
                while (payloads.hasNext()) {
                    if (contents.length() > 0) {
                        contents.append('\n');
                    }
                    contents.append(payloads.next().getValue());
                }
            }
            getPayloadsTextArea().setEnabled(true);
            saveButton.setEnabled(true);
        } catch (Exception e) {
            logger.warn("Failed to read the payloads from the file: {}", e.getMessage(), e);
            contents.setLength(0);
            contents.append(
                    Constant.messages.getString("fuzz.payloads.generator.generic.edit.errorRead"));
        }
        getPayloadsTextArea().setText(contents.toString());
        getPayloadsTextArea().setCaretPosition(0);
        getPayloadsTextArea().discardAllEdits();
    }

    public void clear() {
        getPayloadsTextArea().setText("");
        getPayloadsTextArea().discardAllEdits();
        getPayloadsTextArea().setEnabled(false);
        saveButton.setEnabled(false);
        file = null;
        createTempFile = false;
        externalEditor = false;
        payloadGeneratorUI = null;
    }

    protected static class TextAreaPayloadIterator
            implements ResettableAutoCloseableIterator<DefaultPayload> {

        private final JTextArea payloadsTextArea;
        private final int numberOfPayloads;
        private int line;

        public TextAreaPayloadIterator(JTextArea payloadsTextArea) {
            this.payloadsTextArea = payloadsTextArea;
            this.numberOfPayloads = payloadsTextArea.getLineCount();
        }

        @Override
        public void close() {}

        @Override
        public void remove() {}

        @Override
        public DefaultPayload next() {
            try {
                int offset = payloadsTextArea.getLineStartOffset(line);
                int length = payloadsTextArea.getLineEndOffset(line) - offset;

                line++;
                return new DefaultPayload(payloadsTextArea.getText(offset, length - 1));
            } catch (BadLocationException ignore) {
            }
            return null;
        }

        @Override
        public boolean hasNext() {
            return line < numberOfPayloads;
        }

        @Override
        public void reset() {
            line = 0;
        }
    }
}
