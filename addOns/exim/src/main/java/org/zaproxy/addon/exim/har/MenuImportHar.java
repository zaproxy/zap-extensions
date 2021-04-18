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

import javax.swing.JFileChooser;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.view.ZapMenuItem;

public class MenuImportHar extends ZapMenuItem {

    private static final long serialVersionUID = -9207224834749823025L;
    private static final String THREAD_PREFIX = "ZAP-Import-Har-";

    private int threadId = 1;

    public MenuImportHar() {
        super("exim.har.topmenu.import.importhar");

        this.setToolTipText(
                Constant.messages.getString("exim.har.topmenu.import.importhar.tooltip"));
        this.addActionListener(
                new java.awt.event.ActionListener() {
                    @Override
                    public void actionPerformed(java.awt.event.ActionEvent e) {
                        // Prompt for a file
                        final JFileChooser chooser =
                                new JFileChooser(
                                        Model.getSingleton().getOptionsParam().getUserDirectory());
                        int rc = chooser.showOpenDialog(View.getSingleton().getMainFrame());
                        if (rc == JFileChooser.APPROVE_OPTION) {

                            Thread t =
                                    new Thread() {
                                        @Override
                                        public void run() {
                                            this.setName(THREAD_PREFIX + threadId++);
                                            HarImportUtil.importHarFile(chooser.getSelectedFile());
                                        }
                                    };
                            t.start();
                        }
                    }
                });
    }
}
