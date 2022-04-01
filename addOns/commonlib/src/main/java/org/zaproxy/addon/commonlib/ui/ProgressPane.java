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
package org.zaproxy.addon.commonlib.ui;

import java.awt.EventQueue;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import org.parosproxy.paros.Constant;

/**
 * The progress bar display that is added to the {@link ProgressPanel} to show the details (progress
 * bar and related text messages/updates) for an process (such as OpenAPI import).
 *
 * @since 1.8.0
 */
public class ProgressPane extends JPanel {

    private static final long serialVersionUID = 1L;

    private final JLabel progressStatus;
    private final JProgressBar progressBar;
    private final JLabel currentProgress;
    private boolean completed;
    private boolean indeterminate;

    /**
     * Constructs a progress pane with default title (no resource indication) which includes a
     * determinate progress bar.
     */
    public ProgressPane() {
        this("");
    }

    /**
     * Constructs a progress pane with an extended title including the identified resource (ex: a
     * URL or file system path) which includes a determinate progress bar.
     *
     * @param resource a string representing the location or source of the resource being processed
     *     (ex: a URL or file system path).
     */
    public ProgressPane(String resource) {
        this(resource, false);
    }

    /**
     * Constructs a progress pane with an extended title including the identified resource (ex: a
     * URL or file system path) and indeterminate status indicated.
     *
     * @param resource a string representing the location or source of the resource being processed
     *     (ex: a URL or file system path).
     * @param indeterminate a {@code boolean} indicating whether or not the associated progress bar
     *     should be indeterminate (true) or not (false);
     */
    public ProgressPane(String resource, boolean indeterminate) {
        super(new GridBagLayout());
        this.indeterminate = indeterminate;
        this.setBorder(BorderFactory.createTitledBorder(getTitle(resource)));

        progressStatus = new JLabel();

        progressBar = new JProgressBar();
        progressBar.setStringPainted(true);
        progressBar.setIndeterminate(indeterminate);
        if (indeterminate) {
            progressBar.setString(
                    Constant.messages.getString("commonlib.progress.panel.status.inprogress"));
        }

        currentProgress = new JLabel();

        GridBagConstraints c = new GridBagConstraints();
        c.gridx = 0;
        c.gridy = 0;
        c.weightx = 1;
        c.fill = GridBagConstraints.HORIZONTAL;
        if (!indeterminate) {
            add(progressStatus, c);
        }

        c.gridy++;
        c.ipady = 5;
        c.insets = new Insets(25, 150, 25, 150);
        add(progressBar, c);

        c.gridy++;
        c.ipady = 0;
        c.insets = new Insets(0, 0, 0, 0);
        add(currentProgress, c);

        setTotalTasks(100);
        setCurrentTask("");
    }

    private String getTitle(String resource) {
        if (resource == null || resource.isEmpty()) {
            return Constant.messages.getString("commonlib.progress.pane.title");
        }
        return Constant.messages.getString("commonlib.progress.pane.title.extended", resource);
    }

    /**
     * Sets a message for the item currently being processed as part of the full collection of items
     * (such as a URL).
     *
     * @param text the text to be displayed indicating the item currently being processed.
     */
    public void setCurrentTask(String text) {
        EventQueue.invokeLater(() -> currentProgress.setText(text));
    }

    /**
     * Sets the total number of items to be processed.
     *
     * @param total the total number of items to be processed.
     */
    public void setTotalTasks(int total) {
        EventQueue.invokeLater(
                () -> {
                    progressBar.setMaximum(total);
                    setProcessedTasks(0);
                });
    }

    /**
     * Sets the number of items which have been processed.
     *
     * @param tasksDone the number of items which have been processed.
     */
    public void setProcessedTasks(int tasksDone) {
        EventQueue.invokeLater(
                () -> {
                    progressBar.setValue(tasksDone);
                    progressStatus.setText(
                            Constant.messages.getString(
                                    "commonlib.progress.pane.status",
                                    tasksDone,
                                    progressBar.getMaximum()));
                });
    }

    /**
     * Tells whether the process is complete.
     *
     * @return a boolean indicating whether or not the process is complete.
     */
    public boolean isCompleted() {
        return completed;
    }

    /** Sets the process as having been completed. */
    public void completed() {
        EventQueue.invokeLater(
                () -> {
                    completed = true;
                    if (indeterminate) {
                        progressBar.setString(
                                Constant.messages.getString("commonlib.progress.pane.completed"));
                        progressBar.setIndeterminate(false);
                        progressBar.setValue(100);
                    }
                    currentProgress.setText(
                            Constant.messages.getString("commonlib.progress.pane.completed"));
                });
    }
}
