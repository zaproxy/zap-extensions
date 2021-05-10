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

import java.awt.Component;
import java.awt.HeadlessException;
import java.io.BufferedWriter;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.fuzz.ExtensionFuzz;
import org.zaproxy.zap.extension.fuzz.payloads.Payload;
import org.zaproxy.zap.extension.fuzz.payloads.generator.PayloadGenerator;
import org.zaproxy.zap.extension.fuzz.payloads.ui.PayloadGeneratorUI;
import org.zaproxy.zap.extension.fuzz.payloads.ui.PayloadGeneratorUIPanel;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.utils.ResettableAutoCloseableIterator;

public abstract class AbstractPersistentPayloadGeneratorUIPanel<
                T extends Payload,
                T2 extends PayloadGenerator<T>,
                T3 extends PayloadGeneratorUI<T, T2>>
        implements PayloadGeneratorUIPanel<T, T2, T3> {

    private static final Logger LOGGER =
            LogManager.getLogger(AbstractPersistentPayloadGeneratorUIPanel.class);

    private static final String SAVE_BUTTON_LABEL =
            Constant.messages.getString("fuzz.payloads.generators.save.button");
    private static final String SAVE_BUTTON_TOOL_TIP =
            Constant.messages.getString("fuzz.payloads.generators.save.tooltip");

    private JButton saveButton;

    protected JButton getSaveButton() {
        if (saveButton == null) {
            saveButton = createSaveButton();
        }
        return saveButton;
    }

    protected JButton createSaveButton() {
        JButton saveButton = new JButton(SAVE_BUTTON_LABEL);
        saveButton.setToolTipText(SAVE_BUTTON_TOOL_TIP);
        saveButton.setEnabled(false);
        saveButton.setIcon(
                DisplayUtils.getScaledIcon(
                        new ImageIcon(
                                AbstractPersistentPayloadGeneratorUIPanel.class.getResource(
                                        "/resource/icon/16/096.png"))));
        saveButton.addActionListener(
                e -> {
                    T2 payloadGenerator = getPayloadGenerator();
                    if (payloadGenerator != null) {
                        Path file = getFile();
                        if (file != null) {
                            saveToFile(payloadGenerator, file);
                        }
                    }
                });
        return saveButton;
    }

    private Path getFile() {
        FileChooser fileNameDialogue = new FileChooser();
        if (fileNameDialogue.showSaveDialog(null) != FileChooser.APPROVE_OPTION) {
            return null;
        }
        return fileNameDialogue.getSelectedFile().toPath();
    }

    private void saveToFile(T2 payloadGenerator, Path file) {
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
            addCustomFileFuzzer(file);
        } catch (Exception e) {
            LOGGER.warn(e.getMessage(), e);
            View.getSingleton()
                    .showWarningDialog(
                            Constant.messages.getString(
                                    "fuzz.payloads.generators.save.dialog.warnErrorSaving"));
        }
    }

    private static void addCustomFileFuzzer(Path file) {
        ExtensionFuzz extensionFuzz =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionFuzz.class);
        if (extensionFuzz != null) {
            extensionFuzz.addCustomFileFuzzer(file);
        }
    }

    @Override
    public String getHelpTarget() {
        return "addon.fuzzer.payloads";
    }

    protected abstract T2 getPayloadGenerator();

    private static class FileChooser extends JFileChooser {

        private static final Path BASE_DIR = Paths.get(Constant.getInstance().FUZZER_DIR);

        private static final long serialVersionUID = 7013510209807472291L;

        public FileChooser() {
            super(BASE_DIR.toString());
        }

        @Override
        protected JDialog createDialog(Component parent) throws HeadlessException {
            JDialog dialog = super.createDialog(parent);
            dialog.setIconImages(DisplayUtils.getZapIconImages());
            dialog.setTitle(
                    Constant.messages.getString("fuzz.payloads.generators.save.dialog.title"));
            return dialog;
        }

        @Override
        public void setCurrentDirectory(File dir) {
            if (BASE_DIR.equals(dir.toPath())) {
                super.setCurrentDirectory(dir);
            }
        }

        @Override
        public void changeToParentDirectory() {}

        @Override
        public boolean accept(File file) {
            if (file.isDirectory()) {
                return false;
            }
            return super.accept(file);
        }

        @Override
        public void approveSelection() {
            File selectedFile = getSelectedFile();

            if (!selectedFile.toPath().startsWith(BASE_DIR)
                    || Files.isDirectory(selectedFile.toPath())) {
                JOptionPane.showMessageDialog(
                        null,
                        Constant.messages.getString(
                                "fuzz.payloads.generators.save.dialog.warnInvalidName.message"),
                        Constant.messages.getString(
                                "fuzz.payloads.generators.save.dialog.warnInvalidName.title"),
                        JOptionPane.INFORMATION_MESSAGE);
                return;
            }

            if (Files.exists(selectedFile.toPath())) {
                if (!Files.isWritable(selectedFile.toPath())) {
                    JOptionPane.showMessageDialog(
                            this,
                            Constant.messages.getString(
                                    "fuzz.payloads.generators.save.dialog.warnFileNoWritePermisson.message",
                                    selectedFile.getAbsolutePath()),
                            Constant.messages.getString(
                                    "fuzz.payloads.generators.save.dialog.warnFileNoWritePermisson.title"),
                            JOptionPane.WARNING_MESSAGE);
                    return;
                }

                int result =
                        JOptionPane.showConfirmDialog(
                                this,
                                Constant.messages.getString(
                                        "fuzz.payloads.generators.save.dialog.overwrite.message"),
                                Constant.messages.getString(
                                        "fuzz.payloads.generators.save.dialog.overwrite.title"),
                                JOptionPane.YES_NO_OPTION);
                switch (result) {
                    case JOptionPane.NO_OPTION:
                    case JOptionPane.CLOSED_OPTION:
                        return;
                    case JOptionPane.YES_OPTION:
                }
            } else if (!Files.isWritable(selectedFile.getParentFile().toPath())) {
                JOptionPane.showMessageDialog(
                        this,
                        Constant.messages.getString(
                                "fuzz.payloads.generators.save.dialog.warnDirNoWritePermisson.message",
                                selectedFile.getParentFile().getAbsolutePath()),
                        Constant.messages.getString(
                                "fuzz.payloads.generators.save.dialog.warnDirNoWritePermisson.title"),
                        JOptionPane.WARNING_MESSAGE);
                return;
            }
            super.approveSelection();
        }
    }
}
