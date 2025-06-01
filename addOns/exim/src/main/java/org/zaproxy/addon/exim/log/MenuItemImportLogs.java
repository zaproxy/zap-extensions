/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
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
package org.zaproxy.addon.exim.log;

import java.io.File;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.filechooser.FileFilter;
import javax.swing.filechooser.FileNameExtensionFilter;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.commonlib.ui.ProgressPane;
import org.zaproxy.addon.commonlib.ui.ProgressPaneListener;
import org.zaproxy.addon.commonlib.ui.ReadableFileChooser;
import org.zaproxy.addon.exim.ExtensionExim;
import org.zaproxy.zap.view.ZapMenuItem;

public class MenuItemImportLogs extends ZapMenuItem {

    private static final long serialVersionUID = 9060471082881605934L;

    public MenuItemImportLogs() {
        super("exim.importLogFiles.import.menu.label");

        this.addActionListener(
                e -> {
                    View view = View.getSingleton();
                    JFrame main = view.getMainFrame();
                    JFileChooser fc = new ReadableFileChooser();
                    fc.setAcceptAllFileFilterUsed(false);
                    FileFilter txtFilter =
                            new FileNameExtensionFilter(
                                    Constant.messages.getString(
                                            "exim.importLogFiles.choosefile.filter.txt.description"),
                                    "txt");
                    FileFilter logFilter =
                            new FileNameExtensionFilter(
                                    Constant.messages.getString(
                                            "exim.importLogFiles.choosefile.filter.log.description"),
                                    "log");
                    FileFilter rawFilter =
                            new FileNameExtensionFilter(
                                    Constant.messages.getString(
                                            "exim.importLogFiles.choosefile.filter.raw.description"),
                                    "raw");
                    fc.addChoosableFileFilter(txtFilter);
                    fc.addChoosableFileFilter(logFilter);
                    fc.addChoosableFileFilter(rawFilter);

                    LogsImporter.LogType logChoice =
                            (LogsImporter.LogType)
                                    JOptionPane.showInputDialog(
                                            main,
                                            Constant.messages.getString(
                                                    "exim.importLogFiles.choosefile.message"),
                                            Constant.messages.getString(
                                                    "exim.importLogFiles.choosefile.title"),
                                            JOptionPane.QUESTION_MESSAGE,
                                            null,
                                            LogsImporter.LogType.values(),
                                            LogsImporter.LogType.ZAP);

                    if (logChoice != null) {
                        int openChoice = fc.showOpenDialog(main);
                        if (openChoice == JFileChooser.APPROVE_OPTION) {
                            File newFile = fc.getSelectedFile();
                            ProgressPane currentImportPane =
                                    new ProgressPane(newFile.getAbsolutePath(), true);
                            ExtensionExim.getProgressPanel().addProgressPane(currentImportPane);
                            new LogsImporter(
                                    newFile,
                                    logChoice,
                                    new ProgressPaneListener(currentImportPane));
                        }
                    }
                });
    }
}
