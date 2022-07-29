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
package org.zaproxy.addon.retest;

import java.awt.Frame;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.MouseAdapter;
import java.awt.event.WindowAdapter;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import javax.swing.Box;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JToolBar;
import javax.swing.JTree;
import javax.swing.SwingUtilities;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.TreePath;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jdesktop.swingx.JXTable;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.extension.AbstractDialog;
import org.zaproxy.addon.automation.AutomationEventPublisher;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationPlan;
import org.zaproxy.addon.automation.ExtensionAutomation;
import org.zaproxy.addon.automation.jobs.ActiveScanJob;
import org.zaproxy.addon.automation.jobs.PassiveScanWaitJob;
import org.zaproxy.addon.automation.tests.AbstractAutomationTest;
import org.zaproxy.addon.automation.tests.AutomationAlertTest;
import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.eventBus.Event;
import org.zaproxy.zap.eventBus.EventConsumer;
import org.zaproxy.zap.extension.alert.AlertPanel;
import org.zaproxy.zap.extension.alert.AlertTreeCellRenderer;
import org.zaproxy.zap.extension.alert.ExtensionAlert;
import org.zaproxy.zap.extension.help.ExtensionHelp;

@SuppressWarnings("serial")
public class RetestDialog extends AbstractDialog implements EventConsumer {

    private static final long serialVersionUID = 1L;
    private static final Logger LOG = LogManager.getLogger(RetestDialog.class);
    private ExtensionRetest extension;
    private JPanel jPanel;
    private JToolBar dialogToolbar;
    private JButton addButton;
    private JButton removeButton;
    private JButton editButton;

    private JSplitPane splitPane;
    private JTree treeAlert;
    private JXTable planTable;
    private PlanTableModel planTableModel;
    private JScrollPane alertTreePaneScroll;
    private JScrollPane planPaneScroll;

    private JPanel buttonPanel;
    private JButton verifyButton;
    private JButton createButton;
    private JButton cancelButton;
    private JButton helpButton;

    public RetestDialog(ExtensionRetest extension, Frame frame, boolean modal) {
        super(frame, modal);
        this.extension = extension;
        this.setTitle(Constant.messages.getString("retest.dialog.title"));
        this.setContentPane(getJPanel());
        this.addWindowListener(
                new WindowAdapter() {
                    @Override
                    public void windowClosing(java.awt.event.WindowEvent e) {
                        cancelButton.doClick();
                    }
                });
        pack();
        ZAP.getEventBus()
                .registerConsumer(this, AutomationEventPublisher.getPublisher().getPublisherName());
    }

    private JPanel getJPanel() {
        if (jPanel == null) {
            jPanel = new JPanel();
            jPanel.setLayout(new GridBagLayout());

            GridBagConstraints c = new GridBagConstraints();
            c.gridx = 0;
            c.gridy = 0;
            c.gridwidth = 3;
            c.weightx = 1;
            c.fill = GridBagConstraints.HORIZONTAL;
            jPanel.add(getAlertToolbar(), c);

            c = new GridBagConstraints();
            c.gridx = 0;
            c.gridy = 1;
            c.gridwidth = 3;
            c.weightx = 1;
            c.weighty = 0.6;
            c.fill = GridBagConstraints.BOTH;
            jPanel.add(getSplitPane(), c);

            c = new GridBagConstraints();
            c.gridx = 0;
            c.gridy = 2;
            c.weightx = 0.01;
            c.weighty = 0.2;
            jPanel.add(getHelpButton(), c);

            c = new GridBagConstraints();
            c.gridx = 1;
            c.gridy = 2;
            c.weightx = 0.5;
            c.weighty = 0.2;
            c.fill = GridBagConstraints.BOTH;
            jPanel.add(Box.createHorizontalGlue(), c);

            c = new GridBagConstraints();
            c.gridx = 2;
            c.gridy = 2;
            c.weightx = 0.4;
            c.weighty = 0.2;
            c.fill = GridBagConstraints.BOTH;
            jPanel.add(getButtonPanel(), c);
        }
        return jPanel;
    }

    private JSplitPane getSplitPane() {
        if (splitPane == null) {
            splitPane = new JSplitPane();
            splitPane.setName("RetestPanel");
            splitPane.setDividerSize(3);
            splitPane.setDividerLocation(400);
            splitPane.setOrientation(JSplitPane.HORIZONTAL_SPLIT);

            splitPane.setLeftComponent(getAlertTreePaneScroll());
            splitPane.setRightComponent(getPlanPaneScroll());
        }
        return splitPane;
    }

    private JToolBar getAlertToolbar() {
        if (dialogToolbar == null) {
            dialogToolbar = new JToolBar();
            dialogToolbar.setEnabled(true);
            dialogToolbar.setFloatable(false);
            dialogToolbar.setRollover(true);

            dialogToolbar.add(Box.createHorizontalGlue());
            dialogToolbar.add(getAddButton());
            dialogToolbar.add(getRemoveButton());
            dialogToolbar.add(getEditButton());
        }
        return dialogToolbar;
    }

    private JButton getAddButton() {
        if (addButton == null) {
            addButton = new JButton();
            addButton.setToolTipText(Constant.messages.getString("retest.dialog.add.tooltip"));
            addButton.setIcon(
                    new ImageIcon(AlertPanel.class.getResource("/resource/icon/16/103.png")));
            addButton.addActionListener(
                    actionEvent -> {
                        Set<Alert> selectedAlerts = getSelectedAlertsImpl();
                        for (Alert alert : selectedAlerts) {
                            addAlert(alert);
                        }
                    });
            addButton.setEnabled(false);
        }
        return addButton;
    }

    private Set<Alert> getSelectedAlertsImpl() {
        try {
            TreePath[] paths = getTreeAlert().getSelectionPaths();
            if (paths == null || paths.length == 0) {
                return Collections.emptySet();
            }

            Set<Alert> alerts = new HashSet<>();

            for (TreePath path : paths) {
                DefaultMutableTreeNode alertNode =
                        (DefaultMutableTreeNode) path.getLastPathComponent();
                if (alertNode.getChildCount() == 0) {
                    alerts.add((Alert) alertNode.getUserObject());
                    continue;
                }
                for (int j = 0; j < alertNode.getChildCount(); j++) {
                    DefaultMutableTreeNode node = (DefaultMutableTreeNode) alertNode.getChildAt(j);
                    alerts.add((Alert) node.getUserObject());
                }
            }
            return alerts;
        } catch (Exception e) {
            LOG.error("Failed to access alerts tree", e);
        }
        return new HashSet<>();
    }

    private JButton getRemoveButton() {
        if (removeButton == null) {
            removeButton = new JButton();
            removeButton.setToolTipText(
                    Constant.messages.getString("retest.dialog.remove.tooltip"));
            removeButton.setIcon(
                    new ImageIcon(AlertPanel.class.getResource("/resource/icon/16/104.png")));
            removeButton.addActionListener(
                    actionEvent -> {
                        int[] selectedRows = getPlanTable().getSelectedRows();
                        for (int i = selectedRows.length - 1; i >= 0; i--) {
                            getPlanTableModel()
                                    .removeRow(
                                            getPlanTable().convertRowIndexToModel(selectedRows[i]));
                        }
                    });
            removeButton.setEnabled(false);
        }
        return removeButton;
    }

    private JButton getEditButton() {
        if (editButton == null) {
            editButton = new JButton();
            editButton.setToolTipText(Constant.messages.getString("retest.dialog.edit.tooltip"));
            editButton.setIcon(
                    new ImageIcon(AlertPanel.class.getResource("/resource/icon/16/018.png")));
            editButton.addActionListener(
                    actionEvent -> {
                        int row = getPlanTable().getSelectedRow();
                        EditAlertDialog dialog =
                                new EditAlertDialog(
                                        getPlanTableModel(),
                                        getPlanTable().convertRowIndexToModel(row));
                        dialog.setVisible(true);
                    });
            editButton.setEnabled(false);
        }
        return editButton;
    }

    private JScrollPane getAlertTreePaneScroll() {
        if (alertTreePaneScroll == null) {
            try {
                alertTreePaneScroll = new JScrollPane();
                alertTreePaneScroll.setName("alertTreePaneScroll");
                alertTreePaneScroll.setViewportView(getTreeAlert());
            } catch (Exception e) {
                LOG.error("Failed to access alerts tree", e);
            }
        }
        return alertTreePaneScroll;
    }

    private JTree getTreeAlert()
            throws NoSuchMethodException, IllegalAccessException, InvocationTargetException {
        if (treeAlert == null) {
            ExtensionAlert extAlert =
                    Control.getSingleton().getExtensionLoader().getExtension(ExtensionAlert.class);
            Method alertPanelMethod = extAlert.getClass().getDeclaredMethod("getAlertPanel");
            alertPanelMethod.setAccessible(true);

            AlertPanel panel = (AlertPanel) alertPanelMethod.invoke(extAlert);
            Method alertTreeMethod = panel.getClass().getDeclaredMethod("getTreeAlert");
            alertTreeMethod.setAccessible(true);

            treeAlert = new JTree();
            treeAlert.setModel(((JTree) alertTreeMethod.invoke(panel)).getModel());
            treeAlert.setShowsRootHandles(true);
            treeAlert.setCellRenderer(new AlertTreeCellRenderer());
            treeAlert.setExpandsSelectedPaths(true);
            treeAlert
                    .getSelectionModel()
                    .addTreeSelectionListener(
                            treeSelectionEvent -> getAddButton().setEnabled(true));
        }
        return treeAlert;
    }

    private JScrollPane getPlanPaneScroll() {
        if (planPaneScroll == null) {
            planPaneScroll = new JScrollPane();
            planPaneScroll.setName("planPaneScroll");
            planPaneScroll.setViewportView(getPlanTable());
        }
        return planPaneScroll;
    }

    private JXTable getPlanTable() {
        if (planTable == null) {
            planTable = new JXTable();
            planTable.setModel(getPlanTableModel());
            for (int i = 3; i < planTable.getModel().getColumnCount(); i++) {
                planTable.getColumnExt(getPlanTableModel().getColumnName(i)).setVisible(false);
            }
            planTable.setColumnSelectionAllowed(false);
            planTable.setCellSelectionEnabled(false);
            planTable.setRowSelectionAllowed(true);
            planTable.setAutoCreateRowSorter(true);
            planTable.setHorizontalScrollEnabled(true);
            planTable.setColumnControlVisible(true);
            planTable.addMouseListener(
                    new MouseAdapter() {
                        @Override
                        public void mouseClicked(java.awt.event.MouseEvent e) {
                            if (SwingUtilities.isLeftMouseButton(e) && e.getClickCount() > 1) {
                                getEditButton().doClick();
                            }
                        }
                    });
            planTable
                    .getSelectionModel()
                    .addListSelectionListener(
                            e -> {
                                getRemoveButton()
                                        .setEnabled(getPlanTable().getSelectedRowCount() != 0);
                                getEditButton()
                                        .setEnabled(getPlanTable().getSelectedRowCount() == 1);
                            });
        }
        return planTable;
    }

    public PlanTableModel getPlanTableModel() {
        if (planTableModel == null) {
            planTableModel = new PlanTableModel();
        }
        return planTableModel;
    }

    private JButton getHelpButton() {
        if (helpButton == null) {
            helpButton = new JButton();
            helpButton.setIcon(ExtensionHelp.getHelpIcon());
            helpButton.setToolTipText(Constant.messages.getString("help.dialog.button.tooltip"));
            helpButton.setVisible(true);

            helpButton.addActionListener(
                    e -> {
                        ExtensionHelp.showHelp("retest");
                    });
        }
        return helpButton;
    }

    private JPanel getButtonPanel() {
        if (buttonPanel == null) {
            buttonPanel = new JPanel();
            buttonPanel.setLayout(new GridBagLayout());

            GridBagConstraints c = new GridBagConstraints();
            c.gridx = 0;
            c.gridy = 0;
            c.weightx = 0.33;
            c.fill = GridBagConstraints.HORIZONTAL;
            buttonPanel.add(getVerifyButton(), c);

            c = new GridBagConstraints();
            c.gridx = 1;
            c.gridy = 0;
            c.weightx = 0.33;
            c.fill = GridBagConstraints.HORIZONTAL;
            buttonPanel.add(getCreateButton(), c);

            c = new GridBagConstraints();
            c.gridx = 2;
            c.gridy = 0;
            c.weightx = 0.33;
            c.fill = GridBagConstraints.HORIZONTAL;
            buttonPanel.add(getCancelButton(), c);
        }
        return buttonPanel;
    }

    private JButton getVerifyButton() {
        if (verifyButton == null) {
            verifyButton = new JButton();
            verifyButton.setText(Constant.messages.getString("retest.dialog.button.verify"));
            verifyButton.addActionListener(
                    actionEvent -> {
                        ExtensionAutomation extAutomation =
                                Control.getSingleton()
                                        .getExtensionLoader()
                                        .getExtension(ExtensionAutomation.class);
                        AutomationPlan plan =
                                extension.getPlanForAlerts(planTableModel.getAllRows());
                        extAutomation.registerPlan(plan);
                        extAutomation.loadPlan(plan, false, true);
                    });
        }
        return verifyButton;
    }

    private JButton getCreateButton() {
        if (createButton == null) {
            createButton = new JButton();
            createButton.setText(Constant.messages.getString("retest.dialog.button.create"));
            createButton.addActionListener(
                    actionEvent -> {
                        ExtensionAutomation extAutomation =
                                Control.getSingleton()
                                        .getExtensionLoader()
                                        .getExtension(ExtensionAutomation.class);
                        AutomationPlan plan =
                                extension.getPlanForAlerts(planTableModel.getAllRows());
                        extAutomation.registerPlan(plan);
                        extAutomation.loadPlan(plan, true, false);
                        cancelButton.doClick();
                    });
        }
        return createButton;
    }

    private JButton getCancelButton() {
        if (cancelButton == null) {
            cancelButton = new JButton();
            cancelButton.setText(Constant.messages.getString("retest.dialog.button.cancel"));
            cancelButton.addActionListener(e -> clearAndCloseDialog());
        }
        return cancelButton;
    }

    private void clearAndCloseDialog() {
        getPlanTableModel().clear();
        dispose();
    }

    public void addAlert(Alert alert) {
        Alert copyAlert = alert.newInstance();
        getPlanTableModel().addRow(copyAlert);
    }

    @Override
    public void eventReceived(Event event) {
        SwingUtilities.invokeLater(() -> handleEvent(event));
    }

    private void handleEvent(Event event) {
        if (event.getEventType().equals(AutomationEventPublisher.JOB_FINISHED)) {
            ExtensionAutomation extAutomation =
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionAutomation.class);
            // TODO
            // Tidy up when the TEST_FINISHED event changes are there
            AutomationJob job = extAutomation.getJobByEvent(event);
            ArrayList<AlertData> alertDataList = new ArrayList<>(getPlanTableModel().getAllRows());
            if (job.getType().equals(ActiveScanJob.JOB_NAME)
                    || job.getType().equals(PassiveScanWaitJob.JOB_NAME)) {
                List<AbstractAutomationTest> alertTests = job.getTests();
                for (AbstractAutomationTest test : alertTests) {
                    for (int i = 0; i < alertDataList.size(); i++) {
                        AlertData data = alertDataList.get(i);
                        if (ExtensionRetest.testsForAlert((AutomationAlertTest) test, data)) {
                            if (test.hasPassed()) {
                                data.setStatus(AlertData.Status.ABSENT);
                            } else {
                                data.setStatus(AlertData.Status.PRESENT);
                            }
                            getPlanTableModel().updateRow(i, data);
                        }
                    }
                }
            }
        }
    }
}
