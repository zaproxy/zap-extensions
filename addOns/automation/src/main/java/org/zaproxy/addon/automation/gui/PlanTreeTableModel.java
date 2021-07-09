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

import java.util.HashMap;
import java.util.Map;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jdesktop.swingx.treetable.TreeTableModel;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.automation.AbstractAutomationTest;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationPlan;
import org.zaproxy.addon.automation.AutomationProgress.JobResults;

public class PlanTreeTableModel extends DefaultTreeModel implements TreeTableModel {

    private static final long serialVersionUID = 1L;

    private static final Logger LOG = LogManager.getLogger(PlanTreeTableModel.class);

    public PlanTreeTableModel(DefaultMutableTreeNode root) {
        super(root);
    }

    protected static final int HIERARCHY_INDEX = 0;
    protected static final int STATUS_INDEX = 1;
    protected static final int TYPE_INDEX = 2;
    protected static final int NAME_INDEX = 3;
    protected static final int INFO_INDEX = 4;

    private static final String INDENT = "    ";

    private static final String[] COLUMN_NAMES = {
        "", // The tree control
        Constant.messages.getString("automation.panel.table.header.status"),
        Constant.messages.getString("automation.panel.table.header.type"),
        Constant.messages.getString("automation.panel.table.header.name"),
        Constant.messages.getString("automation.panel.table.header.info")
    };

    private static final int COLUMN_COUNT = COLUMN_NAMES.length;

    private AutomationPlan plan;

    private Map<Object, DefaultMutableTreeNode> map = new HashMap<>();

    @Override
    public DefaultMutableTreeNode getRoot() {
        return (DefaultMutableTreeNode) super.getRoot();
    }

    public void setPlan(AutomationPlan plan) {
        this.plan = plan;
        this.getRoot().removeAllChildren();
        this.getRoot().add(new DefaultMutableTreeNode(plan.getEnv()));
        for (AutomationJob job : plan.getJobs()) {
            DefaultMutableTreeNode jobNode = new DefaultMutableTreeNode(job);
            map.put(job, jobNode);
            this.getRoot().add(jobNode);
            for (AbstractAutomationTest test : job.getTests()) {
                DefaultMutableTreeNode testNode = new DefaultMutableTreeNode(test);
                map.put(test, testNode);
                jobNode.add(testNode);
            }
        }
        this.fireTreeStructureChanged(this, null, null, null);
    }

    @Override
    public String getColumnName(int column) {
        return COLUMN_NAMES[column];
    }

    @Override
    public int getColumnCount() {
        return COLUMN_COUNT;
    }

    @Override
    public Object getValueAt(Object node, int columnIndex) {
        DefaultMutableTreeNode treeNode = (DefaultMutableTreeNode) node;
        Object obj = treeNode.getUserObject();
        if (obj instanceof AutomationEnvironment) {
            AutomationEnvironment env = (AutomationEnvironment) obj;
            switch (columnIndex) {
                case HIERARCHY_INDEX:
                    return "";
                case STATUS_INDEX:
                    if (!env.isCreated()) {
                        return Constant.messages.getString(
                                "automation.panel.table.status.notcreated");
                    } else if (env.hasErrors()) {
                        return Constant.messages.getString("automation.panel.table.status.error");
                    } else if (env.hasWarnings()) {
                        return Constant.messages.getString("automation.panel.table.status.warning");
                    } else {
                        return Constant.messages.getString("automation.panel.table.status.ok");
                    }
                case NAME_INDEX:
                    return Constant.messages.getString("automation.panel.table.env.name");
                case TYPE_INDEX:
                    return "env";
                case INFO_INDEX:
                    return "";
                default:
            }
        } else if (obj instanceof AutomationJob) {
            AutomationJob job = (AutomationJob) obj;
            JobResults jobResults = plan.getProgress().getJobResults(job);
            switch (columnIndex) {
                case STATUS_INDEX:
                    switch (job.getStatus()) {
                        case COMPLETED:
                            if (jobResults == null) {
                                // Can not actually happen, but this keeps LGTM happy ;)
                                return "-";
                            } else if (!jobResults.getErrors().isEmpty()) {
                                return Constant.messages.getString(
                                        "automation.panel.table.status.error");
                            } else if (!jobResults.getWarnings().isEmpty()) {
                                return Constant.messages.getString(
                                        "automation.panel.table.status.warning");
                            } else {
                                return Constant.messages.getString(
                                        "automation.panel.table.status.ok");
                            }
                        case NOT_STARTED:
                            return Constant.messages.getString(
                                    "automation.panel.table.status.notstarted");
                        case RUNNING:
                            return Constant.messages.getString(
                                    "automation.panel.table.status.running");
                        default:
                            break;
                    }
                    return null;
                case NAME_INDEX:
                    return job.getName();
                case TYPE_INDEX:
                    return job.getType();
                case INFO_INDEX:
                    if (jobResults == null) {
                        return "-";
                    } else if (!jobResults.getErrors().isEmpty()) {
                        return Constant.messages.getString(
                                "automation.panel.table.info.error",
                                jobResults.getErrors().toString());
                    } else if (!jobResults.getWarnings().isEmpty()) {
                        return Constant.messages.getString(
                                "automation.panel.table.info.warning",
                                jobResults.getWarnings().toString());
                    } else if (job.getStatus().equals(AutomationJob.Status.NOT_STARTED)) {
                        return Constant.messages.getString(
                                "automation.panel.table.info.config", job.getJobData().toString());
                    } else {
                        return Constant.messages.getString(
                                "automation.panel.table.info.ok", jobResults.getInfos().toString());
                    }
                default:
            }
        } else if (obj instanceof AbstractAutomationTest) {
            AbstractAutomationTest test = (AbstractAutomationTest) obj;
            switch (columnIndex) {
                case STATUS_INDEX:
                    if (!test.hasRun()) {
                        return "";
                    } else if (test.hasPassed()) {
                        return INDENT
                                + Constant.messages.getString(
                                        "automation.panel.table.status.passed");
                    } else {
                        return INDENT
                                + Constant.messages.getString(
                                        "automation.panel.table.status.failed");
                    }
                case NAME_INDEX:
                    return INDENT + test.getName();
                case TYPE_INDEX:
                    return INDENT
                            + Constant.messages.getString(
                                    "automation.panel.table.type.test", test.getTestType());
                case INFO_INDEX:
                    if (!test.hasRun()) {
                        return Constant.messages.getString(
                                "automation.panel.table.info.config",
                                test.getTestData().toString());
                    } else if (test.hasPassed()) {
                        return INDENT + test.getTestPassedMessage();
                    } else {
                        return INDENT + test.getTestFailedMessage();
                    }
                default:
            }
        } else {
            LOG.error("Unexpected obj object " + obj.getClass().getCanonicalName());
            return obj;
        }
        return null;
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return null;
    }

    @Override
    public int getHierarchicalColumn() {
        return HIERARCHY_INDEX;
    }

    @Override
    public boolean isCellEditable(Object node, int column) {
        return false;
    }

    @Override
    public void setValueAt(Object value, Object node, int column) {
        // Not supported
    }

    public void envChanged() {
        // The environment will always be the first node
        if (this.root.getChildCount() > 0) {
            this.fireTreeNodesChanged(
                    this, this.getPathToRoot(this.root.getChildAt(0)), null, null);
        }
    }

    public void jobChanged(AutomationJob job) {
        this.fireTreeNodesChanged(job, this.getPathToRoot(map.get(job)), null, null);
    }
}
