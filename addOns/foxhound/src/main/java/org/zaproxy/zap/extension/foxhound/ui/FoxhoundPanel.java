/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
package org.zaproxy.zap.extension.foxhound.ui;

import static org.zaproxy.zap.extension.foxhound.config.FoxhoundConstants.FOXHOUND_16;

import java.awt.GridBagLayout;
import java.util.List;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JOptionPane;
import javax.swing.JScrollPane;
import javax.swing.JToolBar;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.AbstractPanel;
import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.eventBus.Event;
import org.zaproxy.zap.eventBus.EventConsumer;
import org.zaproxy.zap.extension.foxhound.ExtensionFoxhound;
import org.zaproxy.zap.extension.foxhound.FoxhoundEventPublisher;
import org.zaproxy.zap.extension.foxhound.taint.TaintInfo;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.utils.ThreadUtils;
import org.zaproxy.zap.view.LayoutHelper;

@SuppressWarnings("serial")
public class FoxhoundPanel extends AbstractPanel implements EventConsumer {
    private static final long serialVersionUID = 7L;
    public static final String FOXHOUND_PANEL_NAME = "Foxhound";
    private static final Logger LOGGER = LogManager.getLogger(FoxhoundPanel.class);

    private static final ImageIcon FOXHOUND_ICON =
            DisplayUtils.getScaledIcon(FoxhoundPanel.class.getResource(FOXHOUND_16));

    private static final ImageIcon FILTER_ICON =
            DisplayUtils.getScaledIcon(
                    FoxhoundPanel.class.getResource("/resource/icon/16/054.png"));

    private static final ImageIcon DELETE_ICON =
            DisplayUtils.getScaledIcon(
                    FoxhoundPanel.class.getResource("/resource/icon/16/101.png"));

    private ExtensionFoxhound extension = null;
    private JScrollPane taintFlowScrollPane;
    private JToolBar toolbar;
    private JButton launchButton;
    private JButton clearAllButton;
    private JButton filterButton;
    private TaintFlowTreeTable tree;

    private TaintInfoFilterDialog taintInfoFilterDialog = null;

    public FoxhoundPanel(ExtensionFoxhound extension) {
        super();
        this.extension = extension;
        this.initialize();

        ZAP.getEventBus()
                .registerConsumer(this, FoxhoundEventPublisher.getPublisher().getPublisherName());
    }

    private void initialize() {
        this.setName(Constant.messages.getString("foxhound.panel.title"));
        this.setIcon(FOXHOUND_ICON);
        this.setLayout(new GridBagLayout());

        this.add(this.getToolbar(), LayoutHelper.getGBC(0, 0, 1, 1.0));
        this.add(this.getTaintFlowScrollPane(), LayoutHelper.getGBC(0, 1, 1, 1.0, 1.0));

        this.setShowByDefault(true);
    }

    private JScrollPane getTaintFlowScrollPane() {
        if (taintFlowScrollPane == null) {
            taintFlowScrollPane = new JScrollPane();
            taintFlowScrollPane.setViewportView(getTree());
        }
        return taintFlowScrollPane;
    }

    private TaintFlowTreeTable getTree() {
        if (tree == null) {
            tree = new TaintFlowTreeTable();
        }
        return tree;
    }

    private JToolBar getToolbar() {
        if (toolbar == null) {
            toolbar = new JToolBar();
            toolbar.setFloatable(false);
            toolbar.add(getLaunchButton());
            toolbar.add(getFilterButton());
            toolbar.add(getClearAllButton());
        }
        return toolbar;
    }

    private JButton getLaunchButton() {
        if (launchButton == null) {
            launchButton = new FoxhoundLaunchButton(extension.getSeleniumProfile());
            launchButton.setText(Constant.messages.getString("foxhound.ui.launchText"));
        }
        return launchButton;
    }

    private JButton getClearAllButton() {
        if (clearAllButton == null) {
            clearAllButton = new JButton();
            clearAllButton.setText(Constant.messages.getString("foxhound.ui.clearAll"));
            clearAllButton.setIcon(DELETE_ICON);
            clearAllButton.addActionListener(
                    e -> {
                        extension.getTaintStore().clearAll();
                    });
        }
        return clearAllButton;
    }

    private JButton getFilterButton() {
        if (filterButton == null) {
            filterButton = new JButton();
            filterButton.setText(Constant.messages.getString("foxhound.filter.dialog.open"));
            filterButton.setIcon(FILTER_ICON);
            filterButton.addActionListener(
                    e -> {
                        int res = showFilter();
                        if (res == 1) {
                            List<TaintInfo> taintInfoList =
                                    this.extension
                                            .getTaintStore()
                                            .getFilteredTaintInfos(getFilterDialog().getFilter());
                            this.getTree().getTreeModel().clear();
                            for (TaintInfo t : taintInfoList) {
                                this.getTree().getTreeModel().taintInfoAdded(t);
                            }
                        }
                    });
        }
        return filterButton;
    }

    private TaintInfoFilterDialog getFilterDialog() {
        if (taintInfoFilterDialog == null) {
            taintInfoFilterDialog =
                    new TaintInfoFilterDialog(this.extension.getView().getMainFrame(), true);
        }
        return taintInfoFilterDialog;
    }

    protected int showFilter() {
        TaintInfoFilterDialog dialog = getFilterDialog();
        dialog.setModal(true);

        int exit = dialog.showDialog();
        int result = 0; // cancel, state unchanged
        if (exit == JOptionPane.OK_OPTION) {
            result = 1; // applied

        } else if (exit == JOptionPane.NO_OPTION) {
            result = -1; // reset
        }

        return result;
    }

    @Override
    public void eventReceived(Event event) {
        if (event.getEventType().equals(FoxhoundEventPublisher.TAINT_INFO_CREATED)) {
            String jobIdStr = event.getParameters().get(FoxhoundEventPublisher.JOB_ID);
            if (jobIdStr == null) {
                return;
            }
            int jobId;
            try {
                jobId = Integer.parseInt(jobIdStr);
            } catch (NumberFormatException e) {
                return;
            }
            TaintInfo taintInfo = this.extension.getTaintStore().getTaintInfo(jobId);
            if (taintInfo != null && getFilterDialog().getFilter().matches(taintInfo)) {
                ThreadUtils.invokeLater(
                        () -> {
                            this.tree.getTreeModel().taintInfoAdded(taintInfo);
                        });
            }
        } else if (event.getEventType().equals(FoxhoundEventPublisher.TAINT_INFO_CLEARED)) {
            ThreadUtils.invokeLater(
                    () -> {
                        this.tree.getTreeModel().clear();
                    });
        }
    }
}
