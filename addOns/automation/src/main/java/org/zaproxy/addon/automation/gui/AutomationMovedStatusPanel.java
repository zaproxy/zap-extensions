/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JLabel;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.view.View;
import org.parosproxy.paros.view.WorkbenchPanel;
import org.zaproxy.addon.automation.ExtensionAutomation;
import org.zaproxy.addon.commonlib.ui.TabbedOutputPanel;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.LayoutHelper;

/**
 * A status panel that informs users that the Automation panel has been moved to the main workspace
 * area.
 */
@SuppressWarnings("serial")
public class AutomationMovedStatusPanel extends AbstractPanel {

    private static final ImageIcon ROBOT_INFO_ICON =
            DisplayUtils.getScaledIcon(
                    ExtensionAutomation.class.getResource(
                            ExtensionAutomation.RESOURCES_DIR + "robot-info.png"));

    private final AutomationPanel automationPanel;

    public AutomationMovedStatusPanel(AutomationPanel automationPanel) {
        this.automationPanel = automationPanel;

        setName(Constant.messages.getString("automation.panel.title"));
        setIcon(ROBOT_INFO_ICON);
        setLayout(new GridBagLayout());

        JLabel automationMovedLabel =
                new JLabel(
                        Constant.messages.getString("automation.movedStatusPanel.automationMsg"));
        JLabel outputMovedLabel =
                new JLabel(Constant.messages.getString("automation.movedStatusPanel.outputMsg"));
        JButton showPanelsButton =
                new JButton(Constant.messages.getString("automation.movedStatusPanel.button"));
        showPanelsButton.addActionListener(e -> showAutomationPanels());

        var insets = new Insets(5, 5, 5, 5);
        add(new JLabel(), LayoutHelper.getGBC(0, 0, 1, 1.0)); // Spacer
        add(
                automationMovedLabel,
                LayoutHelper.getGBC(
                        0,
                        1,
                        1,
                        0.0,
                        0.0,
                        GridBagConstraints.NONE,
                        GridBagConstraints.CENTER,
                        insets));
        add(
                outputMovedLabel,
                LayoutHelper.getGBC(
                        0,
                        2,
                        1,
                        0.0,
                        0.0,
                        GridBagConstraints.NONE,
                        GridBagConstraints.CENTER,
                        insets));
        add(
                showPanelsButton,
                LayoutHelper.getGBC(
                        0,
                        3,
                        1,
                        0.0,
                        0.0,
                        GridBagConstraints.NONE,
                        GridBagConstraints.CENTER,
                        insets));
        add(new JLabel(), LayoutHelper.getGBC(0, 4, 1, 1.0)); // Spacer
    }

    private void showAutomationPanels() {
        View.getSingleton().getOutputPanel().setTabFocus();
        if (View.getSingleton().getOutputPanel() instanceof TabbedOutputPanel tabbedOutputPanel) {
            tabbedOutputPanel.setSelectedOutputTab(
                    Constant.messages.getString("automation.output.name"));
        }
        automationPanel.setTabFocus();
        WorkbenchPanel workbench = View.getSingleton().getWorkbench();
        if (workbench.getWorkbenchLayout() == WorkbenchPanel.Layout.FULL) {
            workbench.getTabbedFull().setVisible(this, false);
        } else {
            workbench.getTabbedStatus().setVisible(this, false);
        }
    }
}
