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

    private final JLabel importStatus;
    private final JProgressBar progressBar;
    private final JLabel currentImport;
    private boolean completed;

    public ImportPane() {
        super(new GridBagLayout());
        this.setBorder(
                BorderFactory.createTitledBorder(
                        Constant.messages.getString("openapi.progress.importpane.title")));

        importStatus = new JLabel();

        progressBar = new JProgressBar();
        progressBar.setStringPainted(true);

        currentImport = new JLabel();

        GridBagConstraints c = new GridBagConstraints();
        c.gridx = 0;
        c.gridy = 0;
        c.weightx = 1;
        c.fill = GridBagConstraints.HORIZONTAL;
        add(importStatus, c);

        c.gridy++;
        c.ipady = 5;
        c.insets = new Insets(25, 150, 25, 150);
        add(progressBar, c);

        c.gridy++;
        c.ipady = 0;
        c.insets = new Insets(0, 0, 0, 0);
        add(currentImport, c);

        setTotalEndpoints(100);
        setCurrentImport("");
    }

    public void setCurrentImport(String text) {
        currentImport.setText(
                Constant.messages.getString("openapi.progress.importpane.currentimport", text));
    }

    public void setTotalEndpoints(int total) {
        progressBar.setMaximum(total);
        setImportedEndpoints(0);
    }

    public void setImportedEndpoints(int tasksDone) {
        progressBar.setValue(tasksDone);
        importStatus.setText(
                Constant.messages.getString(
                        "openapi.progress.importpane.status", tasksDone, progressBar.getMaximum()));
    }

    public boolean isCompleted() {
        return completed;
    }

    public void completed() {
        completed = true;
        currentImport.setText(
                Constant.messages.getString("openapi.progress.importpane.import.completed"));
    }
}
