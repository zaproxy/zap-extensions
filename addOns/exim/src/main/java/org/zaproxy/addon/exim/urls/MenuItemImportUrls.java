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
package org.zaproxy.addon.exim.urls;

import java.awt.event.KeyEvent;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.stream.Stream;
import javax.swing.JFileChooser;
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

public class MenuItemImportUrls extends ZapMenuItem {

    private static final long serialVersionUID = 2617077109056192411L;
    private static final Logger LOG = LogManager.getLogger(MenuItemImportUrls.class);
    private static final String THREAD_PREFIX = "ZAP-Exim-Import-Urls-";

    private int threadId = 1;

    public MenuItemImportUrls() {
        super(
                "exim.importurls.topmenu.import",
                View.getSingleton().getMenuShortcutKeyStroke(KeyEvent.VK_I, 0, false));
        this.setToolTipText(Constant.messages.getString("exim.importurls.topmenu.import.tooltip"));
        this.addActionListener(
                e -> {
                    JFileChooser chooser =
                            new ReadableFileChooser(
                                    Model.getSingleton().getOptionsParam().getUserDirectory());
                    int rc = chooser.showOpenDialog(View.getSingleton().getMainFrame());
                    if (rc == JFileChooser.APPROVE_OPTION) {

                        new Thread(
                                        () -> {
                                            File file = chooser.getSelectedFile();
                                            ProgressPane currentImportPane =
                                                    new ProgressPane(file.getAbsolutePath());
                                            currentImportPane.setTotalTasks(getLineCount(file));
                                            ExtensionExim.getProgressPanel()
                                                    .addProgressPane(currentImportPane);
                                            new UrlsImporter(
                                                    file,
                                                    new ProgressPaneListener(currentImportPane));
                                        },
                                        THREAD_PREFIX + threadId++)
                                .start();
                    }
                });
    }

    private static int getLineCount(File file) {
        int lineCount = 0;
        try (Stream<String> stream = Files.lines(file.toPath(), StandardCharsets.UTF_8)) {
            lineCount =
                    (int)
                            stream.filter(line -> !line.startsWith("#") && line.trim().length() > 0)
                                    .count();
        } catch (IOException e) {
            LOG.warn("Couldn't count lines in: {}", file.getAbsoluteFile());
        }
        return lineCount;
    }
}
