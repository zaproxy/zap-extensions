/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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
package org.zaproxy.addon.exim.sites;

import java.io.File;
import javax.swing.JFileChooser;
import javax.swing.filechooser.FileNameExtensionFilter;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.commonlib.ui.ReadableFileChooser;
import org.zaproxy.zap.view.ZapMenuItem;

public class MenuPruneSites extends ZapMenuItem {

    private static final long serialVersionUID = -9207224834749823025L;
    private static final String THREAD_PREFIX = "ZAP-Prune-Sites-";

    private int threadId = 1;

    public MenuPruneSites() {
        super("exim.sites.menu.prune");

        this.setToolTipText(Constant.messages.getString("exim.sites.menu.prune.tooltip"));
        this.addActionListener(
                e -> {
                    FileNameExtensionFilter yamlFilesFilter =
                            new FileNameExtensionFilter(
                                    Constant.messages.getString("exim.file.format.yaml"),
                                    "yaml",
                                    "yml");
                    JFileChooser chooser =
                            new ReadableFileChooser(
                                    Model.getSingleton().getOptionsParam().getUserDirectory());
                    chooser.addChoosableFileFilter(yamlFilesFilter);
                    chooser.setFileFilter(yamlFilesFilter);

                    int rc = chooser.showOpenDialog(View.getSingleton().getMainFrame());
                    if (rc == JFileChooser.APPROVE_OPTION) {
                        Thread t =
                                new Thread() {
                                    @Override
                                    public void run() {
                                        this.setName(THREAD_PREFIX + threadId++);
                                        File file = chooser.getSelectedFile();
                                        PruneSiteResult result =
                                                SitesTreeHandler.pruneSiteNodes(file);

                                        if (result.getError() != null) {
                                            View.getSingleton()
                                                    .showWarningDialog(result.getError());
                                        } else {
                                            View.getSingleton()
                                                    .showMessageDialog(
                                                            Constant.messages.getString(
                                                                    "exim.sites.prune.result",
                                                                    result.getReadNodes(),
                                                                    result.getDeletedNodes()));
                                        }
                                    }
                                };
                        t.start();
                    }
                });
    }
}
