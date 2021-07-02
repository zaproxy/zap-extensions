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
package org.zaproxy.zap.extension.openapi;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import org.parosproxy.paros.Constant;

public class ImportPane extends JPanel {
    private static final long serialVersionUID = 1L;
    private int totalEndpoints;
    private JLabel importStatus = null;
    private JProgressBar progBar = null;
    private JLabel currentImport = null;
    private boolean inProgress = true;

    public ImportPane() {
        super();
        this.setLayout(new GridBagLayout());
        this.setBorder(
                BorderFactory.createTitledBorder(
                        Constant.messages.getString("openapi.progress.importpane.title")));

        GridBagConstraints c = new GridBagConstraints();
        c.gridx = 0;
        c.gridy = 0;
        c.weightx = 1;
        c.fill = GridBagConstraints.HORIZONTAL;
        this.add(getImportStatus(), c);

        c = new GridBagConstraints();
        c.gridx = 0;
        c.gridy = 1;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.weightx = 1;
        c.ipady = 5;
        c.insets = new Insets(25, 150, 25, 150);
        this.add(getProgBar(), c);

        c = new GridBagConstraints();
        c.gridx = 0;
        c.gridy = 2;
        c.weightx = 1;
        c.fill = GridBagConstraints.HORIZONTAL;
        this.add(getCurrentImport(), c);
    }

    private JLabel getImportStatus() {
        if (importStatus == null) {
            importStatus =
                    new JLabel(
                            Constant.messages.getString(
                                    "openapi.progress.importpane.status", 0, totalEndpoints));
        }
        return importStatus;
    }

    public void setImportStatus(String number) {
        importStatus.setText(
                Constant.messages.getString(
                        "openapi.progress.importpane.status", number, totalEndpoints));
    }

    private JProgressBar getProgBar() {
        if (progBar == null) {
            progBar = new JProgressBar(0, 100);
            progBar.setStringPainted(true);
        }
        return progBar;
    }

    private JLabel getCurrentImport() {
        if (currentImport == null) {
            currentImport =
                    new JLabel(
                            Constant.messages.getString(
                                    "openapi.progress.importpane.currentimport", ""));
        }
        return currentImport;
    }

    public void setCurrentImport(String text) {
        currentImport.setText(
                Constant.messages.getString("openapi.progress.importpane.currentimport", text));
    }

    public int getTotalEndpoints() {
        return totalEndpoints;
    }

    public void setTotalEndpoints(int total) {
        totalEndpoints = total;
    }

    public void updateProgBar(int messagesSent) {
        getProgBar().setValue((int) Math.floor((messagesSent * 100) / this.totalEndpoints));
    }

    public boolean getProgressStatus() {
        return inProgress;
    }

    public void setProgressStatus(boolean inProgress) {
        this.inProgress = inProgress;
    }
}
