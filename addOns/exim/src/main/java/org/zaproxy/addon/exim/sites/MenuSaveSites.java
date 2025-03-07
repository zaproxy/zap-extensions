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
import java.util.Locale;
import javax.swing.JFileChooser;
import javax.swing.filechooser.FileNameExtensionFilter;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.exim.ExporterResult;
import org.zaproxy.zap.view.ZapMenuItem;
import org.zaproxy.zap.view.widgets.WritableFileChooser;

public class MenuSaveSites extends ZapMenuItem {

    private static final long serialVersionUID = -9207224834749823025L;

    public MenuSaveSites() {
        super("exim.sites.menu.save");

        this.setToolTipText(Constant.messages.getString("exim.sites.menu.save.tooltip"));
        this.addActionListener(
                e -> {
                    FileNameExtensionFilter yamlFilesFilter =
                            new FileNameExtensionFilter(
                                    Constant.messages.getString("exim.file.format.yaml"),
                                    "yaml",
                                    "yml");
                    JFileChooser chooser =
                            new WritableFileChooser(
                                    Model.getSingleton().getOptionsParam().getUserDirectory());
                    chooser.addChoosableFileFilter(yamlFilesFilter);
                    chooser.setFileFilter(yamlFilesFilter);

                    int rc = chooser.showSaveDialog(View.getSingleton().getMainFrame());
                    if (rc == JFileChooser.APPROVE_OPTION) {
                        String fileName = chooser.getSelectedFile().getAbsolutePath();
                        String fileNameLc = fileName.toLowerCase(Locale.ROOT);
                        if (!fileNameLc.endsWith("yaml") && !fileNameLc.endsWith("yml")) {
                            fileName += ".yaml";
                        }
                        try {
                            SitesTreeHandler.exportSitesTree(
                                    new File(fileName), new ExporterResult());
                        } catch (Exception e1) {
                            View.getSingleton()
                                    .showWarningDialog(
                                            Constant.messages.getString(
                                                    "exim.menu.export.urls.save.error", fileName));
                        }
                    }
                });
    }
}
