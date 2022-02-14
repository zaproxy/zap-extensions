/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.addon.commonlib.ui;

import java.io.File;
import java.nio.file.Files;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.Model;

/**
 * A utility class that provides a {@code JFileChooser} with some basic read permission handling
 *
 * @since 1.8.0
 */
public class ReadableFileChooser extends JFileChooser {

    private static final long serialVersionUID = -8600149638325315048L;

    public ReadableFileChooser() {
        this(null);
    }

    public ReadableFileChooser(File currentDirectory) {
        super(currentDirectory);
        setFileHidingEnabled(false);
    }

    @Override
    public void approveSelection() {
        File selectedFile = getSelectedFile();

        if (!Files.isReadable(selectedFile.toPath())) {
            warnNotReadable(
                    "commonlib.readable.file.chooser.warn.dialog.message",
                    selectedFile.getAbsolutePath());
            return;
        }
        Model.getSingleton().getOptionsParam().setUserDirectory(getCurrentDirectory());
        super.approveSelection();
    }

    /**
     * Convenience method that shows a warning dialogue with the given message and title.
     *
     * <p>The {@code parent} of the warning dialogue is this file chooser.
     *
     * @param message the warning message to display.
     * @param title the title of the dialogue.
     */
    protected void showWarnDialog(String message, String title) {
        JOptionPane.showMessageDialog(this, message, title, JOptionPane.WARNING_MESSAGE);
    }

    private void warnNotReadable(String i18nKeyMessage, String path) {
        showWarnDialog(
                Constant.messages.getString(i18nKeyMessage, path),
                Constant.messages.getString("commonlib.readable.file.chooser.warn.dialog.title"));
    }
}
