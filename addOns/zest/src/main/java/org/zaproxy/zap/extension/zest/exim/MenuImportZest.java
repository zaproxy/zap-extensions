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
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
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
import org.zaproxy.zest.core.v1.ZestElement;
import org.zaproxy.zest.core.v1.ZestJSON;
import org.zaproxy.zest.core.v1.ZestRequest;
import org.zaproxy.zest.core.v1.ZestScript;
import org.zaproxy.zest.core.v1.ZestYaml;

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
                                    new Thread(
                                            () -> {
                                                Thread.currentThread()
                                                        .setName(THREAD_PREFIX + threadId++);
                                                runImport(file);
                                            });
                            t.start();
                        }
                    }
                });
    }

    private void runImport(File file) {
        int tasks = 0;
        try {
            String content = Files.readString(file.toPath(), StandardCharsets.UTF_8);
            ZestScript script = parseScript(content);
            if (script != null) {
                tasks =
                        (int)
                                script.getStatements().stream()
                                        .filter(ZestRequest.class::isInstance)
                                        .count();
            }
        } catch (Exception e) {
            LOGGER.debug("Failed to parse Zest file for task count: {}", e.getMessage());
        }

        ProgressPane currentImportPane = new ProgressPane(file.getAbsolutePath(), false);
        currentImportPane.setTotalTasks(tasks);
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

    private static ZestScript parseScript(String content) {
        if (content == null || content.isBlank()) {
            return null;
        }
        try {
            ZestElement element =
                    content.trim().startsWith("{")
                            ? ZestJSON.fromString(content)
                            : ZestYaml.fromString(content);
            return element instanceof ZestScript ? (ZestScript) element : null;
        } catch (Exception e) {
            LOGGER.debug("Failed to parse Zest script: {}", e.getMessage());
            return null;
        }
    }
}
