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

import java.awt.GridBagLayout;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.util.List;

import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextPane;
import javax.swing.JToolBar;
import javax.swing.filechooser.FileFilter;
import javax.swing.text.BadLocationException;
import javax.swing.text.Style;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;
import javax.swing.tree.DefaultMutableTreeNode;

import org.jdesktop.swingx.JXTreeTable;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.automation.AutomationEventPublisher;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationJobException;
import org.zaproxy.addon.automation.AutomationPlan;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.automation.ExtensionAutomation;
import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.eventBus.Event;
import org.zaproxy.zap.eventBus.EventConsumer;
import org.zaproxy.zap.view.LayoutHelper;

public class AutomationPanel extends AbstractPanel implements EventConsumer {

    private static final long serialVersionUID = 1L;

    private static final ImageIcon PLAY_ICON =
            new ImageIcon(AutomationPanel.class.getResource("/resource/icon/16/131.png"));
    protected static final ImageIcon GREEN_BALL_ICON =
            new ImageIcon(AutomationPanel.class.getResource("/resource/icon/16/152.png"));
    protected static final ImageIcon RED_BALL_ICON =
            new ImageIcon(AutomationPanel.class.getResource("/resource/icon/16/151.png"));
    protected static final ImageIcon YELLOW_BALL_ICON =
            new ImageIcon(AutomationPanel.class.getResource("/resource/icon/16/154.png"));
    protected static final ImageIcon ORANGE_BALL_ICON =
            new ImageIcon(AutomationPanel.class.getResource("/resource/icon/16/156.png"));
    protected static final ImageIcon WHITE_BALL_ICON =
            new ImageIcon(AutomationPanel.class.getResource("/resource/icon/16/160.png"));

    private ExtensionAutomation ext;
    private JToolBar toolbar;
    private JScrollPane planScrollpane;
    private JButton loadPlanButton;
    private JButton runPlanButton;
    private JTabbedPane tabbedPane;
    private JXTreeTable tree;
    private PlanTreeTableModel treeModel;
    private JScrollPane outputScrollpane;
    private JTextPane outputArea;
    private AutomationPlan currentPlan;
    private Style styleError;
    private Style styleWarning;
    private Style styleInfo;

    public AutomationPanel(ExtensionAutomation ext) {
        this.ext = ext;
        this.setName(Constant.messages.getString("automation.panel.title"));
        this.setIcon(ExtensionAutomation.ICON);
        this.setLayout(new GridBagLayout());

        this.add(this.getToolbar(), LayoutHelper.getGBC(0, 0, 1, 1.0));
        this.add(this.getTabbedPane(), LayoutHelper.getGBC(0, 1, 1, 1.0, 1.0));

        ZAP.getEventBus()
                .registerConsumer(this, AutomationEventPublisher.getPublisher().getPublisherName());
    }

    private JToolBar getToolbar() {
        if (toolbar == null) {
            toolbar = new JToolBar();
            toolbar.setFloatable(false);
            toolbar.add(this.getLoadPlanButton());
            toolbar.add(this.getRunPlanButton());
        }
        return toolbar;
    }

    private JButton getRunPlanButton() {
        if (runPlanButton == null) {
            runPlanButton = new JButton();
            runPlanButton.setIcon(PLAY_ICON);
            runPlanButton.setEnabled(false);
            runPlanButton.addActionListener(
                    e -> {
                        if (currentPlan == null) {
                            return;
                        }
                        new Thread(
                                        () -> {
                                            try {
                                                ext.runPlan(currentPlan, true);
                                            } catch (AutomationJobException e1) {
                                                View.getSingleton()
                                                        .showWarningDialog(e1.getMessage());
                                            }
                                        },
                                        "ZAP-Automation")
                                .start();
                    });
        }
        return runPlanButton;
    }

    private JButton getLoadPlanButton() {
        if (loadPlanButton == null) {
            loadPlanButton = new JButton();
            loadPlanButton.setIcon(
                    new ImageIcon(getClass().getResource("/resource/icon/16/047.png")));
            loadPlanButton.addActionListener(
                    e -> {
                        final JFileChooser chooser =
                                new JFileChooser(ext.getParam().getPlanDirectory());
                        chooser.setAcceptAllFileFilterUsed(false);
                        chooser.addChoosableFileFilter(
                                new FileFilter() {

                                    @Override
                                    public boolean accept(File f) {
                                        String lcFileName = f.getName().toLowerCase();
                                        return (f.isDirectory()
                                                || lcFileName.endsWith(".yaml")
                                                || lcFileName.endsWith(".yml"));
                                    }

                                    @Override
                                    public String getDescription() {
                                        return Constant.messages.getString(
                                                "automation.panel.load.yaml");
                                    }
                                });
                        int rc = chooser.showOpenDialog(View.getSingleton().getMainFrame());
                        if (rc == JFileChooser.APPROVE_OPTION) {
                            ext.getParam()
                                    .setPlanDirectory(
                                            chooser.getSelectedFile()
                                                    .getParentFile()
                                                    .getAbsolutePath());
                            loadPlan(chooser.getSelectedFile());
                        }
                    });
        }
        return loadPlanButton;
    }

    private void loadPlan(File f) {
        try {
            setCurrentPlan(ext.loadPlan(f));
            ext.registerPlan(currentPlan);
            AutomationProgress progress = currentPlan.getProgress();
            this.getOutputArea().setText(listToStr(progress.getAllMessages()));
            if (progress.hasErrors()) {
                View.getSingleton()
                        .showWarningDialog(
                                Constant.messages.getString(
                                        "automation.panel.load.error",
                                        listToStr(progress.getErrors())));
            } else if (progress.hasWarnings()) {
                View.getSingleton()
                        .showWarningDialog(
                                Constant.messages.getString(
                                        "automation.panel.load.warning",
                                        listToStr(progress.getWarnings())));
            }

        } catch (Exception e) {
            View.getSingleton()
                    .showWarningDialog(
                            Constant.messages.getString(
                                    "automation.panel.load.failed", e.getMessage()));
        }
    }

    public void setCurrentPlan(AutomationPlan plan) {
        currentPlan = plan;
        getTreeModel().setPlan(currentPlan);
        getRunPlanButton().setEnabled(currentPlan != null);
    }

    private JTabbedPane getTabbedPane() {
        if (this.tabbedPane == null) {
            this.tabbedPane = new JTabbedPane();
            this.tabbedPane.addTab("Plan", this.getPlanScrollpane());
            this.tabbedPane.addTab("Output", getOutputScrollpane());
        }
        return this.tabbedPane;
    }

    private JScrollPane getPlanScrollpane() {
        if (planScrollpane == null) {
            planScrollpane = new JScrollPane();
            tree = new JXTreeTable();
            tree.setTreeTableModel(getTreeModel());
            tree.setTreeCellRenderer(new PlanTreeNodeCellRenderer());
            planScrollpane.setViewportView(tree);
            // TODO WIP
            tree.addMouseListener(new MouseAdapter() {
            	@Override
            	public void mouseClicked(MouseEvent me) {
            		if (me.getClickCount() == 2) {
            			int row = tree.getSelectedRow();
            			System.out.println("SBSB Row: " + row); // TODO
            		}
            	}
            });
        }
        return planScrollpane;
    }

    private JScrollPane getOutputScrollpane() {
        if (outputScrollpane == null) {
            outputScrollpane = new JScrollPane();
            outputScrollpane.setViewportView(this.getOutputArea());
        }
        return outputScrollpane;
    }

    private JTextPane getOutputArea() {
        if (outputArea == null) {
            outputArea = new JTextPane();
            outputArea.setEditable(false);
            styleError = this.getOutputArea().addStyle("Error", null);
            StyleConstants.setIcon(styleError, RED_BALL_ICON);

            styleWarning = this.getOutputArea().addStyle("Warning", null);
            StyleConstants.setIcon(styleWarning, ORANGE_BALL_ICON);

            styleInfo = this.getOutputArea().addStyle("Info", null);
            StyleConstants.setIcon(styleInfo, WHITE_BALL_ICON);
        }
        return outputArea;
    }

    private PlanTreeTableModel getTreeModel() {
        if (treeModel == null) {
            treeModel = new PlanTreeTableModel(new DefaultMutableTreeNode("Plan"));
        }
        return treeModel;
    }

    private static String listToStr(List<String> list) {
        return String.join("\n", list);
    }

    private void outputMessage(String message, Style style) {
        StyledDocument doc = this.getOutputArea().getStyledDocument();
        try {
            doc.insertString(doc.getLength(), " ", style);
            doc.insertString(doc.getLength(), "  " + message + "\n", null);
        } catch (BadLocationException e) {
            // Ignore
        }
    }

    private AutomationPlan getPlan(Event event) {
        String planIdStr = event.getParameters().get(AutomationEventPublisher.PLAN_ID);
        if (planIdStr == null) {
            return null;
        }
        int planId;
        try {
            planId = Integer.parseInt(planIdStr);
        } catch (NumberFormatException e) {
            return null;
        }
        return ext.getPlan(planId);
    }

    private AutomationJob getJob(Event event) {
        AutomationPlan plan = this.getPlan(event);
        if (plan == null) {
            return null;
        }
        String jobIdStr = event.getParameters().get(AutomationEventPublisher.JOB_ID);
        if (jobIdStr == null) {
            return null;
        }
        int jobId;
        try {
            jobId = Integer.parseInt(jobIdStr);
        } catch (NumberFormatException e) {
            return null;
        }
        return plan.getJob(jobId);
    }

    private void updateJob(Event event) {
        AutomationJob job = this.getJob(event);
        if (job != null) {
            getTreeModel().jobChanged(job);
        }
    }

    @Override
    public void eventReceived(Event event) {
        switch (event.getEventType()) {
            case AutomationEventPublisher.PLAN_STARTED:
                this.getOutputArea().setText("");
                break;
            case AutomationEventPublisher.PLAN_ERROR_MESSAGE:
                outputMessage(
                        event.getParameters().get(AutomationEventPublisher.MESSAGE), styleError);
                break;
            case AutomationEventPublisher.PLAN_WARNING_MESSAGE:
                outputMessage(
                        event.getParameters().get(AutomationEventPublisher.MESSAGE), styleWarning);
                break;
            case AutomationEventPublisher.PLAN_INFO_MESSAGE:
                outputMessage(
                        event.getParameters().get(AutomationEventPublisher.MESSAGE), styleInfo);
                break;
            case AutomationEventPublisher.PLAN_ENV_CREATED:
                getTreeModel().envChanged();
                break;
            case AutomationEventPublisher.JOB_STARTED:
                updateJob(event);
                break;
            case AutomationEventPublisher.JOB_FINISHED:
                updateJob(event);
                break;
            default:
                // Ignore
                break;
        }
    }
}
