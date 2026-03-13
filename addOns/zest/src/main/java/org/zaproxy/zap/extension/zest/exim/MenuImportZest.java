/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.zap.extension.zest.exim;

import java.io.File;
import javax.swing.JFileChooser;
import javax.swing.filechooser.FileNameExtensionFilter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.commonlib.ui.ProgressPane;
import org.zaproxy.addon.commonlib.ui.ProgressPaneListener;
import org.zaproxy.addon.commonlib.ui.ReadableFileChooser;
import org.zaproxy.addon.exim.ExtensionExim;
import org.zaproxy.zap.view.ZapMenuItem;

public class MenuImportZest extends ZapMenuItem {

    private static final long serialVersionUID = 1L;
    private static final Logger LOGGER = LogManager.getLogger(MenuImportZest.class);
    private static final String THREAD_PREFIX = "ZAP-Import-Zest-";

    private int threadId = 1;

    public MenuImportZest() {
        super("zest.exim.topmenu.import");

        setToolTipText(Constant.messages.getString("zest.exim.topmenu.import.tooltip"));
        addActionListener(
                e -> {
                    JFileChooser chooser =
                            new ReadableFileChooser(
                                    Model.getSingleton().getOptionsParam().getUserDirectory());
                    chooser.setFileFilter(
                            new FileNameExtensionFilter(
                                    Constant.messages.getString("zest.exim.file.description"),
                                    "zst"));
                    int rc = chooser.showOpenDialog(View.getSingleton().getMainFrame());
                    if (rc == JFileChooser.APPROVE_OPTION) {
                        File file = chooser.getSelectedFile();
                        if (file != null) {
                            Thread t =
                                    new Thread(() -> runImport(file), THREAD_PREFIX + threadId++);
                            t.start();
                        }
                    }
                });
    }

    private void runImport(File file) {
        ProgressPane currentImportPane = new ProgressPane(file.getAbsolutePath(), false);
        ExtensionExim.getProgressPanel().addProgressPane(currentImportPane);

        ZestImporter importer = new ZestImporter(file, new ProgressPaneListener(currentImportPane));

        if (!importer.isSuccess()) {
            String errorMsg =
                    importer.getLastError() != null
                            ? Constant.messages.getString(
                                    "zest.exim.file.import.error.with.reason",
                                    file.getAbsolutePath(),
                                    importer.getLastError())
                            : Constant.messages.getString(
                                    "zest.exim.file.import.error", file.getAbsolutePath());
            ExtensionExim.updateOutput(ExtensionExim.EXIM_OUTPUT_ERROR, errorMsg);
            View.getSingleton().showWarningDialog(errorMsg);
        }
    }
}
