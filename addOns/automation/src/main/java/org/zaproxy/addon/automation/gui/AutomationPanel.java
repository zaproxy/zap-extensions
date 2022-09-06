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

import com.fasterxml.jackson.core.JsonProcessingException;
import java.awt.GridBagLayout;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import javax.swing.Box;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextPane;
import javax.swing.JToolBar;
import javax.swing.SwingUtilities;
import javax.swing.filechooser.FileFilter;
import javax.swing.text.BadLocationException;
import javax.swing.text.Style;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.TreePath;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jdesktop.swingx.JXTreeTable;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationEventPublisher;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationPlan;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.automation.ExtensionAutomation;
import org.zaproxy.addon.automation.tests.AbstractAutomationTest;
import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.eventBus.Event;
import org.zaproxy.zap.eventBus.EventConsumer;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.LayoutHelper;

@SuppressWarnings("serial")
public class AutomationPanel extends AbstractPanel implements EventConsumer {

    private static final long serialVersionUID = 1L;

    private static final ImageIcon PLAY_ICON =
            DisplayUtils.getScaledIcon(
                    new ImageIcon(AutomationPanel.class.getResource("/resource/icon/16/131.png")));
    private static final ImageIcon LOAD_ICON =
            DisplayUtils.getScaledIcon(
                    new ImageIcon(AutomationPanel.class.getResource("/resource/icon/16/047.png")));
    private static final ImageIcon SAVE_ICON =
            DisplayUtils.getScaledIcon(
                    new ImageIcon(AutomationPanel.class.getResource("/resource/icon/16/096.png")));
    private static final ImageIcon SAVE_AS_ICON =
            DisplayUtils.getScaledIcon(
                    new ImageIcon(
                            AutomationPanel.class.getResource(
                                    ExtensionAutomation.RESOURCES_DIR + "save-as.png")));
    private static final ImageIcon ADD_PLAN_ICON =
            DisplayUtils.getScaledIcon(
                    new ImageIcon(
                            AutomationPanel.class.getResource(
                                    ExtensionAutomation.RESOURCES_DIR + "clipboard--plus.png")));
    private static final ImageIcon DOWN_ARROW_ICON =
            DisplayUtils.getScaledIcon(
                    new ImageIcon(
                            AutomationPanel.class.getResource(
                                    ExtensionAutomation.RESOURCES_DIR + "task-move-down.png")));
    private static final ImageIcon UP_ARROW_ICON =
            DisplayUtils.getScaledIcon(
                    new ImageIcon(
                            AutomationPanel.class.getResource(
                                    ExtensionAutomation.RESOURCES_DIR + "task-move-up.png")));
    private static final ImageIcon ADD_JOB_ICON =
            DisplayUtils.getScaledIcon(
                    new ImageIcon(
                            AutomationPanel.class.getResource(
                                    ExtensionAutomation.RESOURCES_DIR + "task--plus.png")));
    private static final ImageIcon REMOVE_JOB_ICON =
            DisplayUtils.getScaledIcon(
                    new ImageIcon(
                            AutomationPanel.class.getResource(
                                    ExtensionAutomation.RESOURCES_DIR + "task--minus.png")));
    private static final ImageIcon ADD_TEST_ICON =
            DisplayUtils.getScaledIcon(
                    new ImageIcon(
                            AutomationPanel.class.getResource(
                                    ExtensionAutomation.RESOURCES_DIR + "question-plus.png")));
    private static final ImageIcon REMOVE_TEST_ICON =
            DisplayUtils.getScaledIcon(
                    new ImageIcon(
                            AutomationPanel.class.getResource(
                                    ExtensionAutomation.RESOURCES_DIR + "question-minus.png")));

    protected static final ImageIcon GREEN_BALL_ICON =
            DisplayUtils.getScaledIcon(
                    new ImageIcon(AutomationPanel.class.getResource("/resource/icon/16/152.png")));
    protected static final ImageIcon RED_BALL_ICON =
            DisplayUtils.getScaledIcon(
                    new ImageIcon(AutomationPanel.class.getResource("/resource/icon/16/151.png")));
    protected static final ImageIcon YELLOW_BALL_ICON =
            DisplayUtils.getScaledIcon(
                    new ImageIcon(AutomationPanel.class.getResource("/resource/icon/16/154.png")));
    protected static final ImageIcon ORANGE_BALL_ICON =
            DisplayUtils.getScaledIcon(
                    new ImageIcon(AutomationPanel.class.getResource("/resource/icon/16/156.png")));
    protected static final ImageIcon WHITE_BALL_ICON =
            DisplayUtils.getScaledIcon(
                    new ImageIcon(AutomationPanel.class.getResource("/resource/icon/16/160.png")));

    private static final Logger LOG = LogManager.getLogger(AutomationPanel.class);

    private ExtensionAutomation ext;
    private JToolBar toolbar;
    private JScrollPane planScrollpane;
    private JButton loadPlanButton;
    private JButton addPlanButton;
    private JButton runPlanButton;
    private JButton savePlanButton;
    private JButton saveAsPlanButton;
    private JButton jobUpButton;
    private JButton jobDownButton;
    private JButton addJobButton;
    private JButton removeJobButton;
    private JTabbedPane tabbedPane;
    private JButton addTestButton;
    private JButton removeTestButton;
    private JButton optionsButton;
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
            toolbar.add(getAddPlanButton());
            toolbar.add(getLoadPlanButton());
            toolbar.add(getSavePlanButton());
            toolbar.add(getSaveAsPlanButton());
            toolbar.add(getRunPlanButton());
            toolbar.addSeparator();
            toolbar.add(getAddJobButton());
            toolbar.add(getRemoveJobButton());
            toolbar.add(getJobUpButton());
            toolbar.add(getJobDownButton());
            toolbar.add(getAddTestButton());
            toolbar.add(getRemoveTestButton());

            toolbar.add(Box.createHorizontalGlue());
            toolbar.add(getOptionsButton());
        }
        return toolbar;
    }

    private JButton getRunPlanButton() {
        if (runPlanButton == null) {
            runPlanButton = new JButton();
            runPlanButton.setIcon(PLAY_ICON);
            runPlanButton.setToolTipText(Constant.messages.getString("automation.dialog.plan.run"));
            runPlanButton.setEnabled(false);
            runPlanButton.addActionListener(
                    e -> {
                        if (currentPlan == null) {
                            return;
                        }
                        ext.runPlanAsync(currentPlan);
                    });
        }
        return runPlanButton;
    }

    private void savePlan(boolean promptForFile) {
        if (currentPlan == null) {
            return;
        }
        try {
            if (promptForFile) {
                final JFileChooser chooser = new JFileChooser(ext.getParam().getPlanDirectory());
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
                                return Constant.messages.getString("automation.panel.load.yaml");
                            }
                        });
                int rc = chooser.showSaveDialog(View.getSingleton().getMainFrame());
                if (rc == JFileChooser.APPROVE_OPTION) {
                    ext.getParam()
                            .setPlanDirectory(
                                    chooser.getSelectedFile().getParentFile().getAbsolutePath());
                    File f = chooser.getSelectedFile();
                    String fileNameLc = f.getName().toLowerCase(Locale.ROOT);
                    if (!f.exists()
                            && !(fileNameLc.endsWith(".yaml") || fileNameLc.endsWith(".yml"))) {
                        f = new File(f.getAbsolutePath() + ".yaml");
                    }
                    currentPlan.setFile(f);
                } else {
                    // they cancelled the dialog
                    return;
                }
            }
            currentPlan.save();
            ext.getParam().setLastPlanPath(currentPlan.getFile().getAbsolutePath());
        } catch (JsonProcessingException | FileNotFoundException e1) {
            LOG.error(e1.getMessage(), e1);
            View.getSingleton()
                    .showWarningDialog(
                            Constant.messages.getString(
                                    "automation.dialog.error.save", e1.getMessage()));
        }
    }

    private JButton getSavePlanButton() {
        if (savePlanButton == null) {
            savePlanButton = new JButton();
            savePlanButton.setIcon(SAVE_ICON);
            savePlanButton.setToolTipText(
                    Constant.messages.getString("automation.dialog.plan.save"));
            savePlanButton.setEnabled(false);
            savePlanButton.addActionListener(
                    e -> savePlan(currentPlan != null && currentPlan.getFile() == null));
        }
        return savePlanButton;
    }

    private JButton getSaveAsPlanButton() {
        if (saveAsPlanButton == null) {
            saveAsPlanButton = new JButton();
            saveAsPlanButton.setIcon(SAVE_AS_ICON);
            saveAsPlanButton.setToolTipText(
                    Constant.messages.getString("automation.dialog.plan.save-as"));
            saveAsPlanButton.setEnabled(false);
            saveAsPlanButton.addActionListener(e -> savePlan(true));
        }
        return saveAsPlanButton;
    }

    private JButton getLoadPlanButton() {
        if (loadPlanButton == null) {
            loadPlanButton = new JButton();
            loadPlanButton.setIcon(LOAD_ICON);
            loadPlanButton.setToolTipText(
                    Constant.messages.getString("automation.dialog.plan.load"));
            loadPlanButton.addActionListener(
                    e -> {
                        if (currentPlan != null && currentPlan.isChanged()) {
                            if (JOptionPane.OK_OPTION
                                    != View.getSingleton()
                                            .showConfirmDialog(
                                                    Constant.messages.getString(
                                                            "automation.dialog.plan.loosechanges"))) {
                                return;
                            }
                        }
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
            loadPlan(ext.loadPlan(f));
            ext.getParam().setLastPlanPath(f.getAbsolutePath());
        } catch (Exception e) {
            LOG.error(e.getMessage(), e);
            View.getSingleton()
                    .showWarningDialog(
                            Constant.messages.getString(
                                    "automation.panel.load.failed", e.getMessage()));
        }
    }

    private Object setSelectedItem() {
        TreePath path = tree.getPathForRow(tree.getSelectedRow());
        if (path != null) {
            Object node = path.getLastPathComponent();
            if (node instanceof DefaultMutableTreeNode) {
                return ((DefaultMutableTreeNode) node).getUserObject();
            }
        }
        return null;
    }

    private JButton getAddPlanButton() {
        if (addPlanButton == null) {
            addPlanButton = new JButton();
            addPlanButton.setIcon(ADD_PLAN_ICON);
            addPlanButton.setToolTipText(Constant.messages.getString("automation.dialog.plan.new"));
            addPlanButton.addActionListener(
                    e -> {
                        if (currentPlan != null
                                && currentPlan.isChanged()
                                && JOptionPane.OK_OPTION
                                        != View.getSingleton()
                                                .showConfirmDialog(
                                                        Constant.messages.getString(
                                                                "automation.dialog.plan.loosechanges"))) {
                            return;
                        }
                        new NewPlanDialog().setVisible(true);
                    });
        }
        return addPlanButton;
    }

    private JButton getJobUpButton() {
        if (jobUpButton == null) {
            jobUpButton = new JButton();
            jobUpButton.setIcon(UP_ARROW_ICON);
            jobUpButton.setToolTipText(Constant.messages.getString("automation.dialog.job.moveup"));
            jobUpButton.setEnabled(false);
            jobUpButton.addActionListener(
                    e -> {
                        if (currentPlan == null) {
                            return;
                        }
                        int row = tree.getSelectedRow();
                        if (row <= 1) {
                            // The environment or first job
                            return;
                        }
                        Object userObj = setSelectedItem();
                        if (userObj instanceof AutomationJob) {
                            AutomationJob job = (AutomationJob) userObj;
                            if (currentPlan.moveJobUp(job)) {
                                getTreeModel().moveJobUp(job);
                                // TODO this isnt working :(
                                tree.setRowSelectionInterval(row - 1, row - 1);
                                job.setChanged();
                            }
                        }
                    });
        }
        return jobUpButton;
    }

    private JButton getJobDownButton() {
        if (jobDownButton == null) {
            jobDownButton = new JButton();
            jobDownButton.setIcon(DOWN_ARROW_ICON);
            jobDownButton.setToolTipText(
                    Constant.messages.getString("automation.dialog.job.movedown"));
            jobDownButton.setEnabled(false);
            jobDownButton.addActionListener(
                    e -> {
                        if (currentPlan == null) {
                            return;
                        }
                        int row = tree.getSelectedRow();
                        if (row <= 0) {
                            // The environment
                            return;
                        }
                        if (row == currentPlan.getJobsCount()) {
                            // The last node (the env will be index 0)
                            return;
                        }
                        Object userObj = setSelectedItem();
                        if (userObj instanceof AutomationJob) {
                            AutomationJob job = (AutomationJob) userObj;
                            if (currentPlan.moveJobDown(job)) {
                                getTreeModel().moveJobDown(job);
                                // TODO this isnt working :(
                                tree.setRowSelectionInterval(row + 1, row + 1);
                                job.setChanged();
                            }
                        }
                    });
        }
        return jobDownButton;
    }

    private JButton getAddJobButton() {
        if (addJobButton == null) {
            addJobButton = new JButton();
            addJobButton.setIcon(ADD_JOB_ICON);
            addJobButton.setToolTipText(Constant.messages.getString("automation.dialog.job.add"));
            addJobButton.setEnabled(false);
            addJobButton.addActionListener(
                    e -> {
                        if (currentPlan == null) {
                            return;
                        }
                        new AddJobDialog(currentPlan).setVisible(true);
                    });
        }
        return addJobButton;
    }

    private JButton getRemoveJobButton() {
        if (removeJobButton == null) {
            removeJobButton = new JButton();
            removeJobButton.setIcon(REMOVE_JOB_ICON);
            removeJobButton.setToolTipText(
                    Constant.messages.getString("automation.dialog.job.remove"));
            removeJobButton.setEnabled(false);
            removeJobButton.addActionListener(
                    e -> {
                        if (currentPlan == null) {
                            return;
                        }
                        Object userObj = setSelectedItem();
                        if (userObj instanceof AutomationJob) {
                            AutomationJob job = (AutomationJob) userObj;
                            if (JOptionPane.OK_OPTION
                                            == View.getSingleton()
                                                    .showConfirmDialog(
                                                            Constant.messages.getString(
                                                                    "automation.dialog.job.remove.confirm"))
                                    && currentPlan.removeJob(job)) {
                                getTreeModel().removeJob(job);
                            }
                        }
                    });
        }
        return removeJobButton;
    }

    private JButton getAddTestButton() {
        if (addTestButton == null) {
            addTestButton = new JButton();
            addTestButton.setIcon(ADD_TEST_ICON);
            addTestButton.setToolTipText(Constant.messages.getString("automation.dialog.test.add"));
            addTestButton.setEnabled(false);
            addTestButton.addActionListener(
                    e -> {
                        if (currentPlan == null) {
                            return;
                        }
                        Object userObj = setSelectedItem();
                        if (userObj instanceof AutomationJob) {
                            AutomationJob job = (AutomationJob) userObj;
                            new AddTestDialog(job).setVisible(true);
                        }
                    });
        }
        return addTestButton;
    }

    private JButton getRemoveTestButton() {
        if (removeTestButton == null) {
            removeTestButton = new JButton();
            removeTestButton.setIcon(REMOVE_TEST_ICON);
            removeTestButton.setToolTipText(
                    Constant.messages.getString("automation.dialog.test.remove"));
            removeTestButton.setEnabled(false);
            removeTestButton.addActionListener(
                    e -> {
                        if (currentPlan == null) {
                            return;
                        }
                        Object userObj = setSelectedItem();
                        if (userObj instanceof AbstractAutomationTest) {
                            AbstractAutomationTest test = (AbstractAutomationTest) userObj;
                            if (JOptionPane.OK_OPTION
                                            == View.getSingleton()
                                                    .showConfirmDialog(
                                                            Constant.messages.getString(
                                                                    "automation.dialog.test.remove.confirm"))
                                    && test.getJob().removeTest(test)) {
                                AutomationEventPublisher.publishEvent(
                                        AutomationEventPublisher.TEST_REMOVED, test.getJob(), null);
                                getTreeModel().removeTest(test);
                            }
                        }
                    });
        }
        return removeTestButton;
    }

    private JButton getOptionsButton() {
        if (optionsButton == null) {
            optionsButton = new JButton();
            optionsButton.setToolTipText(Constant.messages.getString("automation.dialog.options"));
            optionsButton.setIcon(
                    DisplayUtils.getScaledIcon(
                            new ImageIcon(ZAP.class.getResource("/resource/icon/16/041.png"))));

            optionsButton.addActionListener(
                    e ->
                            Control.getSingleton()
                                    .getMenuToolsControl()
                                    .options(
                                            Constant.messages.getString(
                                                    "automation.optionspanel.name")));
        }
        return optionsButton;
    }

    public void loadPlan(AutomationPlan plan) {
        setCurrentPlan(plan);
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
    }

    public void setCurrentPlan(AutomationPlan plan) {
        currentPlan = plan;
        getTreeModel().setPlan(currentPlan);
        getRunPlanButton().setEnabled(currentPlan != null);
        getAddJobButton().setEnabled(currentPlan != null);
        getSavePlanButton().setEnabled(false);
        getSaveAsPlanButton().setEnabled(currentPlan != null);
    }

    public List<String> getUnsavedPlans() {
        if (currentPlan != null && currentPlan.isChanged()) {
            List<String> list = new ArrayList<>();
            list.add(Constant.messages.getString("automation.plan.current.unsaved"));
            return list;
        }
        return Collections.emptyList();
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
            tree.addMouseListener(
                    new MouseAdapter() {
                        @Override
                        public void mouseClicked(MouseEvent me) {
                            if (me.getClickCount() == 2) {
                                Object userObj = setSelectedItem();
                                if (userObj instanceof AutomationEnvironment) {
                                    ((AutomationEnvironment) userObj).showDialog();
                                } else if (userObj instanceof AutomationJob) {
                                    ((AutomationJob) userObj).setJobData(null);
                                    ((AutomationJob) userObj).showDialog();
                                } else if (userObj instanceof AbstractAutomationTest) {
                                    ((AbstractAutomationTest) userObj).showDialog();
                                } else if (userObj != null) {
                                    LOG.error(
                                            "Unsupported automation framework tree node class {}",
                                            userObj.getClass().getCanonicalName());
                                }
                            }
                        }
                    });
            tree.getSelectionModel()
                    .addListSelectionListener(
                            e -> {
                                int row = tree.getSelectedRow();
                                if (currentPlan == null || row < 0) {
                                    disableJobAndTestButtons();
                                    return;
                                }
                                Object userObj = setSelectedItem();
                                if (userObj instanceof AutomationJob) {
                                    getJobUpButton().setEnabled(row > 1);
                                    getJobDownButton().setEnabled(row < currentPlan.getJobsCount());
                                    getRemoveJobButton().setEnabled(true);
                                    getAddTestButton().setEnabled(true);
                                } else if (userObj instanceof AbstractAutomationTest) {
                                    disableJobAndTestButtons();
                                    getRemoveTestButton().setEnabled(true);
                                } else {
                                    disableJobAndTestButtons();
                                }
                            });
        }
        return planScrollpane;
    }

    private void disableJobAndTestButtons() {
        getJobUpButton().setEnabled(false);
        getJobDownButton().setEnabled(false);
        getRemoveJobButton().setEnabled(false);
        getAddTestButton().setEnabled(false);
        getRemoveTestButton().setEnabled(false);
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

    public AutomationJob getJob(Event event) {
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

    private void updateSaveButton(Event event, boolean enable) {
        AutomationPlan plan = this.getPlan(event);
        if (plan != null && plan.equals(this.currentPlan)) {
            getSavePlanButton().setEnabled(enable);
        }
    }

    @Override
    public void eventReceived(Event event) {
        SwingUtilities.invokeLater(() -> handleEvent(event));
    }

    private void handleEvent(Event event) {
        AutomationPlan plan;
        LOG.debug("Event: {}", event.getEventType());
        switch (event.getEventType()) {
            case AutomationEventPublisher.PLAN_CREATED:
            case AutomationEventPublisher.PLAN_CHANGED:
                updateSaveButton(event, true);
                break;
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
            case AutomationEventPublisher.PLAN_SAVED:
                updateSaveButton(event, false);
                break;
            case AutomationEventPublisher.JOB_STARTED:
                updateJob(event);
                break;
            case AutomationEventPublisher.JOB_FINISHED:
                updateJob(event);
                break;
            case AutomationEventPublisher.JOB_ADDED:
            case AutomationEventPublisher.TEST_ADDED:
                plan = this.getPlan(event);
                getTreeModel().setPlan(plan);
                updateSaveButton(event, true);
                break;
            case AutomationEventPublisher.JOB_CHANGED:
                updateJob(event);
                updateSaveButton(event, true);
                break;
            default:
                // Ignore
                break;
        }
    }
}
