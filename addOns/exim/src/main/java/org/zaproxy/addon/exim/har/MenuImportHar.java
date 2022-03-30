/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.addon.exim.har;

import edu.umass.cs.benchlab.har.tools.HarFileReader;
import java.io.File;
import java.io.IOException;
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

public class MenuImportHar extends ZapMenuItem {

    private static final long serialVersionUID = -9207224834749823025L;
    private static final Logger LOG = LogManager.getLogger(MenuImportHar.class);
    private static final String THREAD_PREFIX = "ZAP-Import-Har-";

    private int threadId = 1;

    public MenuImportHar() {
        super("exim.har.topmenu.import.importhar");

        this.setToolTipText(
                Constant.messages.getString("exim.har.topmenu.import.importhar.tooltip"));
        this.addActionListener(
                e -> {
                    JFileChooser chooser =
                            new ReadableFileChooser(
                                    Model.getSingleton().getOptionsParam().getUserDirectory());
                    int rc = chooser.showOpenDialog(View.getSingleton().getMainFrame());
                    if (rc == JFileChooser.APPROVE_OPTION) {

                        Thread t =
                                new Thread() {
                                    @Override
                                    public void run() {
                                        this.setName(THREAD_PREFIX + threadId++);
                                        File file = chooser.getSelectedFile();
                                        int tasks = 0;
                                        boolean indeterminate;
                                        try {
                                            tasks =
                                                    new HarFileReader()
                                                            .readHarFile(file)
                                                            .getEntries()
                                                            .getEntries()
                                                            .size();
                                            indeterminate = false;
                                        } catch (IOException e) {
                                            indeterminate = true;
                                            LOG.warn(
                                                    "Couldn't count entries in: {}",
                                                    file.getAbsoluteFile());
                                        }
                                        ProgressPane currentImportPane =
                                                new ProgressPane(
                                                        file.getAbsolutePath(), indeterminate);
                                        currentImportPane.setTotalTasks(tasks);
                                        ExtensionExim.getProgressPanel()
                                                .addProgressPane(currentImportPane);
                                        HarImporter harImporter =
                                                new HarImporter(
                                                        file,
                                                        new ProgressPaneListener(
                                                                currentImportPane));
                                        if (!harImporter.isSuccess()) {
                                            View.getSingleton()
                                                    .showWarningDialog(
                                                            Constant.messages.getString(
                                                                    "exim.har.file.import.error",
                                                                    file.getAbsolutePath()));
                                        }
                                    }
                                };
                        t.start();
                    }
                });
    }
}
