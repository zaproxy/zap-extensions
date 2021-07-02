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
package org.zaproxy.zap.extension.openapi;

import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.util.ArrayList;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JToolBar;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.AbstractPanel;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.utils.FontUtils;

public class ProgressPanel extends AbstractPanel {
    private static final long serialVersionUID = 1L;

    @SuppressWarnings("unused")
    private ExtensionOpenApi extension = null;

    private static final ImageIcon PROGRESS_ICON =
            new ImageIcon(
                    ProgressPanel.class.getResource(
                            "/org/zaproxy/zap/extension/openapi/resources/ui-progress-bar-indeterminate.png"));
    private JToolBar toolBar = null;
    private JScrollPane jScrollPane = null;
    private JPanel importProgressPanel = null;
    private JPanel importPanesPanel = null;
    private ArrayList<ImportPane> importPanes = new ArrayList<>();
    private GridBagConstraints panelConstraints;

    public ProgressPanel(ExtensionOpenApi extension) {
        super();
        this.extension = extension;
        this.setLayout(new CardLayout());
        this.setName(Constant.messages.getString("openapi.progress.panel.title"));
        this.setIcon(PROGRESS_ICON);
        this.setDefaultAccelerator(
                this.extension
                        .getView()
                        .getMenuShortcutKeyStroke(KeyEvent.VK_M, KeyEvent.SHIFT_DOWN_MASK, false));
        this.setMnemonic(Constant.messages.getChar("openapi.progress.panel.mnemonic"));
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
        this.add(getImportProgressPanel(), getImportPanesPanel().getName());
    }

    private JPanel getImportProgressPanel() {
        if (importProgressPanel == null) {
            importProgressPanel = new JPanel(new BorderLayout());
            importProgressPanel.setName("ProgressPanel");
            importProgressPanel.add(getToolBar(), BorderLayout.PAGE_START);
            importProgressPanel.add(getJScrollPane(), BorderLayout.CENTER);
        }
        return importProgressPanel;
    }

    @SuppressWarnings("unchecked")
    private JToolBar getToolBar() {
        if (toolBar == null) {
            toolBar = new JToolBar();
            toolBar.setFloatable(false);
            toolBar.setRollover(true);

            JButton clearButton =
                    new JButton(
                            Constant.messages.getString("openapi.progress.panel.button.clear"),
                            DisplayUtils.getScaledIcon(
                                    ProgressPanel.class.getResource(
                                            "/resource/icon/fugue/broom.png")));
            clearButton.addActionListener(e -> this.clear());

            JComboBox<String> statusCombo = new JComboBox<String>();
            statusCombo.addItem(Constant.messages.getString("openapi.progress.panel.status.all"));
            statusCombo.addItem(
                    Constant.messages.getString("openapi.progress.panel.status.completed"));
            statusCombo.addItem(
                    Constant.messages.getString("openapi.progress.panel.status.inprogress"));
            statusCombo.setSelectedIndex(0);
            // TODO : Change to not use setMaximumSize
            statusCombo.setMaximumSize(new Dimension(150, Integer.MAX_VALUE));
            statusCombo.addActionListener(
                    new ActionListener() {
                        public void actionPerformed(ActionEvent e) {
                            JComboBox<String> combo = (JComboBox<String>) e.getSource();
                            updateImportPanesPanel((String) combo.getSelectedItem());
                        }
                    });

            JLabel showLabel =
                    new JLabel(Constant.messages.getString("openapi.progress.panel.status.show"));
            showLabel.setLabelFor(statusCombo);

            toolBar.add(clearButton);
            toolBar.add(showLabel);
            toolBar.add(statusCombo);
        }
        return toolBar;
    }

    private JScrollPane getJScrollPane() {
        if (jScrollPane == null) {
            jScrollPane = new JScrollPane(getImportPanesPanel());
            jScrollPane.setFont(FontUtils.getFont("Dialog"));
            jScrollPane.setVerticalScrollBarPolicy(
                    javax.swing.JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        }
        return jScrollPane;
    }

    private JPanel getImportPanesPanel() {
        if (importPanesPanel == null) {
            importPanesPanel = new JPanel();
            importPanesPanel.setLayout(new GridBagLayout());
        }
        return importPanesPanel;
    }

    private void updateImportPanesPanel(String status) {
        getImportPanesPanel().removeAll();
        panelConstraints.gridy = 0;
        for (ImportPane pane : importPanes) {
            if ((status.equals("Completed") && !pane.getProgressStatus())
                    || (status.equals("In Progress") && pane.getProgressStatus())
                    || status.equals("All")) {
                getImportPanesPanel().add(pane, panelConstraints);
                panelConstraints.gridy++;
            }
        }
        getImportPanesPanel().revalidate();
        getImportPanesPanel().repaint();
    }

    public void addImportPane(ImportPane pane) {
        importPanes.add(pane);
        getImportPanesPanel().add(pane, panelConstraints);
        panelConstraints.gridy++;
    }

    private void clear() {
        ArrayList<ImportPane> panesToRemove = new ArrayList<>();
        for (ImportPane pane : importPanes) {
            if (!pane.getProgressStatus()) {
                getImportPanesPanel().remove(pane);
                panesToRemove.add(pane);
            }
        }
        importPanes.removeAll(panesToRemove);
        getImportPanesPanel().revalidate();
        getImportPanesPanel().repaint();
    }

    public void clearAndDispose() {
        getImportPanesPanel().removeAll();
        getImportPanesPanel().revalidate();
        getImportPanesPanel().repaint();
        importPanes.clear();
        panelConstraints.gridy = 0;
    }
}
