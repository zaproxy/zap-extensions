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

/**
 * A listener object to be implemented by classes which implement some sort of process for which
 * displaying progress is beneficial (such as importing).
 *
 * @since 1.8.0
 */
public class ProgressPaneListener {

    private final ProgressPane progressPane;
    private int tasksDone;

    /**
     * Constructs a listener for the given {@link ProgressPane}.
     *
     * @param progressPane the pane the listener pertains to.
     */
    public ProgressPaneListener(ProgressPane progressPane) {
        this.progressPane = progressPane;
    }

    /**
     * Returns the {@link ProgressPane} which is associated with this listener.
     *
     * @return the {@link ProgressPane} which is associated with this listener.
     */
    protected ProgressPane getProgressPane() {
        return progressPane;
    }

    /**
     * Gets the number of tasks which have been processed.
     *
     * @return the number of tasks which have been processed.
     */
    protected int getTasksDone() {
        return tasksDone;
    }

    /**
     * Sets the number of tasks which have been processed.
     *
     * @param tasksDone the number of tasks which have been processed.
     */
    public void setTasksDone(int tasksDone) {
        getProgressPane().setProcessedTasks(tasksDone);
        this.tasksDone = tasksDone;
    }

    /**
     * Sets the description of the task currently being processed.
     *
     * @param task the description of the task currently being processed.
     */
    public void setCurrentTask(String task) {
        progressPane.setCurrentTask(task);
    }

    /** Sets the completed state of the {@code ProgressPane}. */
    public void completed() {
        progressPane.completed();
    }
}
