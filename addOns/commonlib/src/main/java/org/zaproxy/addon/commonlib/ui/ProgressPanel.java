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

import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Dimension;
import java.awt.EventQueue;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.KeyEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JToolBar;
import javax.swing.JToolBar.Separator;
import javax.swing.ScrollPaneConstants;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.extension.ViewDelegate;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.utils.FontUtils;

/**
 * The panel which displays {@link ProgressPane}s with progress bars and text messages providing
 * updates as to the status of various processes.
 *
 * @since 1.8.0
 */
@SuppressWarnings("serial")
public class ProgressPanel extends AbstractPanel {

    private enum DisplayStatus {
        ALL("all", pane -> true),
        COMPLETED("completed", ProgressPane::isCompleted),
        IN_PROGRESS("inprogress", pane -> !pane.isCompleted());

        private final String label;
        private final Predicate<ProgressPane> condition;

        DisplayStatus(String statusKey, Predicate<ProgressPane> condition) {
            label = Constant.messages.getString("commonlib.progress.panel.status." + statusKey);
            this.condition = condition;
        }

        boolean matches(ProgressPane pane) {
            return condition.test(pane);
        }

        @Override
        public String toString() {
            return label;
        }
    }

    private static final long serialVersionUID = 1L;

    private static final ImageIcon PROGRESS_ICON =
            new ImageIcon(
                    ProgressPanel.class.getResource(
                            "/org/zaproxy/addon/commonlib/resources/ui-progress-bar-indeterminate.png"));
    private JToolBar toolBar = null;
    private JScrollPane jScrollPane = null;
    private JPanel progressPanel = null;
    private JPanel progressPanesPanel = null;
    private List<ProgressPane> progressPanes = new ArrayList<>();
    private GridBagConstraints panelConstraints;

    public ProgressPanel(ViewDelegate view) {
        super();
        this.setLayout(new CardLayout());
        this.setName(Constant.messages.getString("commonlib.progress.panel.title"));
        this.setIcon(PROGRESS_ICON);
        this.setDefaultAccelerator(
                view.getMenuShortcutKeyStroke(
                        KeyEvent.VK_M, java.awt.event.InputEvent.SHIFT_DOWN_MASK, false));
        this.setMnemonic(Constant.messages.getChar("commonlib.progress.panel.mnemonic"));
        this.panelConstraints =
                new GridBagConstraints(
                        0,
                        0,
                        1,
                        1,
                        1,
                        1,
                        GridBagConstraints.PAGE_START,
                        GridBagConstraints.HORIZONTAL,
                        new Insets(0, 0, 0, 0),
                        0,
                        0);
        this.add(getProgressPanel(), getProgressPanesPanel().getName());
    }

    private JPanel getProgressPanel() {
        if (progressPanel == null) {
            progressPanel = new JPanel(new BorderLayout());
            progressPanel.setName("ProgressPanel");
            progressPanel.add(getToolBar(), BorderLayout.PAGE_START);
            progressPanel.add(getJScrollPane(), BorderLayout.CENTER);
        }
        return progressPanel;
    }

    private JToolBar getToolBar() {
        if (toolBar == null) {
            toolBar = new JToolBar();
            toolBar.setFloatable(false);
            toolBar.setRollover(true);

            JButton clearButton =
                    new JButton(
                            Constant.messages.getString("commonlib.progress.panel.button.clear"),
                            DisplayUtils.getScaledIcon(
                                    ProgressPanel.class.getResource(
                                            "/resource/icon/fugue/broom.png")));
            clearButton.addActionListener(e -> this.clear());

            JComboBox<DisplayStatus> statusCombo = new JComboBox<>();
            statusCombo.addItem(DisplayStatus.ALL);
            statusCombo.addItem(DisplayStatus.COMPLETED);
            statusCombo.addItem(DisplayStatus.IN_PROGRESS);
            statusCombo.setSelectedIndex(0);
            // TODO : Change to not use setMaximumSize
            statusCombo.setMaximumSize(new Dimension(150, Integer.MAX_VALUE));
            statusCombo.addActionListener(
                    e -> updateProgressPanesPanel((DisplayStatus) statusCombo.getSelectedItem()));

            JLabel showLabel =
                    new JLabel(Constant.messages.getString("commonlib.progress.panel.status.show"));
            showLabel.setLabelFor(statusCombo);

            toolBar.add(clearButton);
            toolBar.add(new Separator());
            toolBar.add(showLabel);
            toolBar.add(statusCombo);
        }
        return toolBar;
    }

    private JScrollPane getJScrollPane() {
        if (jScrollPane == null) {
            jScrollPane = new JScrollPane(getProgressPanesPanel());
            jScrollPane.setFont(FontUtils.getFont("Dialog"));
            jScrollPane.setVerticalScrollBarPolicy(
                    ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED);
        }
        return jScrollPane;
    }

    private JPanel getProgressPanesPanel() {
        if (progressPanesPanel == null) {
            progressPanesPanel = new JPanel();
            progressPanesPanel.setLayout(new GridBagLayout());
        }
        return progressPanesPanel;
    }

    private void updateProgressPanesPanel(DisplayStatus status) {
        getProgressPanesPanel().removeAll();
        panelConstraints.gridy = 0;
        for (ProgressPane pane : progressPanes) {
            if (status.matches(pane)) {
                getProgressPanesPanel().add(pane, panelConstraints);
                panelConstraints.gridy++;
            }
        }
        getProgressPanesPanel().revalidate();
        getProgressPanesPanel().repaint();
    }

    /**
     * Adds the given {@link ProgressPane} to be displayed.
     *
     * @param pane the {@link ProgressPane} to be displayed.
     */
    public void addProgressPane(ProgressPane pane) {
        EventQueue.invokeLater(
                () -> {
                    if (progressPanes.isEmpty()) {
                        this.setTabFocus();
                    }
                    progressPanes.add(pane);
                    getProgressPanesPanel().add(pane, panelConstraints);
                    panelConstraints.gridy++;
                });
    }

    private void clear() {
        List<ProgressPane> panesToRemove = new ArrayList<>();
        for (ProgressPane pane : progressPanes) {
            if (pane.isCompleted()) {
                getProgressPanesPanel().remove(pane);
                panesToRemove.add(pane);
            }
        }
        progressPanes.removeAll(panesToRemove);
        getProgressPanesPanel().revalidate();
        getProgressPanesPanel().repaint();
    }

    /** Clears and disposes of all the {@link ProgressPane}s which are currently being displayed. */
    public void clearAndDispose() {
        EventQueue.invokeLater(
                () -> {
                    getProgressPanesPanel().removeAll();
                    getProgressPanesPanel().revalidate();
                    getProgressPanesPanel().repaint();
                    progressPanes.clear();
                    panelConstraints.gridy = 0;
                });
    }
}
