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
package org.zaproxy.addon.exim.pcap;

import java.io.File;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.filechooser.FileFilter;
import javax.swing.filechooser.FileNameExtensionFilter;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.commonlib.ui.ProgressPane;
import org.zaproxy.addon.commonlib.ui.ProgressPaneListener;
import org.zaproxy.addon.commonlib.ui.ReadableFileChooser;
import org.zaproxy.addon.exim.ExtensionExim;
import org.zaproxy.zap.view.ZapMenuItem;

public class MenuItemImportPcap extends ZapMenuItem {
    private static final long serialVersionUID = 9111279126644588074L;

    public MenuItemImportPcap() {
        super("exim.import.pcap.topmenu.import");
        this.setToolTipText(Constant.messages.getString("exim.import.pcap.topmenu.import.tooltip"));

        this.addActionListener(
                e -> {
                    View view = View.getSingleton();
                    JFrame main = view.getMainFrame();
                    JFileChooser fc = new ReadableFileChooser();
                    fc.setAcceptAllFileFilterUsed(false);
                    FileFilter pcapFilter =
                            new FileNameExtensionFilter(
                                    Constant.messages.getString(
                                            "exim.import.pcap.choosefile.filter.pcap.description"),
                                    "pcap");
                    FileFilter pcapngFilter =
                            new FileNameExtensionFilter(
                                    Constant.messages.getString(
                                            "exim.import.pcap.choosefile.filter.pcapng.description"),
                                    "pcapng");
                    fc.addChoosableFileFilter(pcapFilter);
                    fc.addChoosableFileFilter(pcapngFilter);

                    int openChoice = fc.showOpenDialog(main);
                    if (openChoice == JFileChooser.APPROVE_OPTION) {
                        File newFile = fc.getSelectedFile();
                        ProgressPane currentImportPane =
                                new ProgressPane(newFile.getAbsolutePath(), true);
                        ExtensionExim.getProgressPanel().addProgressPane(currentImportPane);
                        new PcapImporter(newFile, new ProgressPaneListener(currentImportPane));
                    }
                });
    }
}
