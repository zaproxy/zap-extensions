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
package org.zaproxy.addon.automation.gui;

import java.awt.Component;
import javax.swing.JTree;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeCellRenderer;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationProgress.JobResults;
import org.zaproxy.addon.automation.tests.AbstractAutomationTest;

public class PlanTreeNodeCellRenderer extends DefaultTreeCellRenderer {

    private static final long serialVersionUID = 1L;

    @Override
    public Component getTreeCellRendererComponent(
            JTree tree,
            Object value,
            boolean sel,
            boolean expanded,
            boolean leaf,
            int row,
            boolean hasFocus) {

        super.getTreeCellRendererComponent(tree, value, sel, expanded, leaf, row, hasFocus);

        if (!(value instanceof DefaultMutableTreeNode)) {
            return this;
        }

        DefaultMutableTreeNode node = (DefaultMutableTreeNode) value;
        Object obj = node.getUserObject();
        if (obj == null) {
            return this;
        }
        if (obj instanceof AutomationEnvironment) {
            AutomationEnvironment env = (AutomationEnvironment) obj;
            if (!env.isCreated()) {
                this.setIcon(AutomationPanel.WHITE_BALL_ICON);
            } else if (env.hasErrors()) {
                this.setIcon(AutomationPanel.RED_BALL_ICON);
            } else if (env.hasWarnings()) {
                this.setIcon(AutomationPanel.ORANGE_BALL_ICON);
            } else {
                this.setIcon(AutomationPanel.GREEN_BALL_ICON);
            }
        } else if (obj instanceof AutomationJob) {
            AutomationJob job = (AutomationJob) obj;
            switch (job.getStatus()) {
                case COMPLETED:
                    JobResults jobResults = job.getPlan().getProgress().getJobResults(job);
                    if (!jobResults.getErrors().isEmpty()) {
                        this.setIcon(AutomationPanel.RED_BALL_ICON);
                    } else if (!jobResults.getWarnings().isEmpty()) {
                        this.setIcon(AutomationPanel.ORANGE_BALL_ICON);
                    } else {
                        this.setIcon(AutomationPanel.GREEN_BALL_ICON);
                    }
                    break;
                case NOT_STARTED:
                    this.setIcon(AutomationPanel.WHITE_BALL_ICON);
                    break;
                case RUNNING:
                    this.setIcon(AutomationPanel.YELLOW_BALL_ICON);
                    break;
                default:
                    break;
            }
        } else if (obj instanceof AbstractAutomationTest) {
            AbstractAutomationTest test = (AbstractAutomationTest) obj;
            if (!test.hasRun()) {
                this.setIcon(AutomationPanel.WHITE_BALL_ICON);
            } else if (test.hasPassed()) {
                this.setIcon(AutomationPanel.GREEN_BALL_ICON);
            } else {
                this.setIcon(AutomationPanel.RED_BALL_ICON);
            }
        }
        setText("");

        return this;
    }
}
