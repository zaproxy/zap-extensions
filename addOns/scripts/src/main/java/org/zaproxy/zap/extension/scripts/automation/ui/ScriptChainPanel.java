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
package org.zaproxy.zap.extension.scripts.automation.ui;

import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Window;
import java.awt.event.ActionListener;
import java.util.Arrays;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.border.EmptyBorder;
import javax.swing.event.ListSelectionListener;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.scripts.automation.ScriptJob;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.LayoutHelper;

@SuppressWarnings("serial")
class ScriptChainPanel extends JPanel {

    private static final String TITLE_AVAILABLE = "scripts.automation.dialog.chain.available";
    private static final String TITLE_SELECTED = "scripts.automation.dialog.chain.selected";
    private static final String CLEAR_ALL_CONFIRM =
            "scripts.automation.dialog.chain.clearAllConfirm";

    private static final String TRANSFER_ADD_TOOLTIP =
            "scripts.automation.dialog.chain.transfer.add.tooltip";
    private static final String TRANSFER_ADD_ALL_TOOLTIP =
            "scripts.automation.dialog.chain.transfer.addAll.tooltip";
    private static final String TRANSFER_REMOVE_TOOLTIP =
            "scripts.automation.dialog.chain.transfer.remove.tooltip";
    private static final String TRANSFER_CLEAR_TOOLTIP =
            "scripts.automation.dialog.chain.transfer.clear.tooltip";

    private final ScriptJob job;
    private final DefaultListModel<String> chainModel;
    private final DefaultListModel<String> sourceModel = new DefaultListModel<>();
    private final JList<String> sourceList = new JList<>(sourceModel);
    private final JList<String> chainList;
    private final JButton[] transferButtons = new JButton[4];
    private final JButton[] reorderButtons = new JButton[4];

    ScriptChainPanel(ScriptJob job, DefaultListModel<String> chainModel) {
        super(new GridBagLayout());
        this.job = job;
        this.chainModel = chainModel;
        this.chainList = new JList<>(chainModel);
        setBorder(new EmptyBorder(8, 8, 8, 8));

        sourceList.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        chainList.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);

        add(
                new JLabel(Constant.messages.getString(TITLE_AVAILABLE)),
                LayoutHelper.getGBC(
                        0, 0, 1, 0.0, 0.0, GridBagConstraints.WEST, new Insets(0, 0, 4, 4)));
        add(
                new JLabel(Constant.messages.getString(TITLE_SELECTED)),
                LayoutHelper.getGBC(
                        2, 0, 1, 0.0, 0.0, GridBagConstraints.WEST, new Insets(0, 0, 4, 4)));

        JScrollPane sourceScrollPane = new JScrollPane(sourceList);
        sourceScrollPane.setPreferredSize(DisplayUtils.getScaledDimension(220, 240));
        add(
                sourceScrollPane,
                LayoutHelper.getGBC(
                        0, 1, 1, 1.0, 1.0, GridBagConstraints.BOTH, new Insets(0, 0, 4, 4)));

        buildTransferButtons();
        add(
                verticalButtonPanel(transferButtons, true),
                LayoutHelper.getGBC(
                        1,
                        1,
                        1,
                        1,
                        0.0,
                        1.0,
                        GridBagConstraints.NONE,
                        GridBagConstraints.CENTER,
                        new Insets(0, 0, 4, 4)));

        JScrollPane chainScrollPane = new JScrollPane(chainList);
        chainScrollPane.setPreferredSize(DisplayUtils.getScaledDimension(220, 240));
        add(
                chainScrollPane,
                LayoutHelper.getGBC(
                        2, 1, 1, 1.0, 1.0, GridBagConstraints.BOTH, new Insets(0, 0, 4, 4)));

        buildReorderButtons();
        add(
                verticalButtonPanel(reorderButtons, false),
                LayoutHelper.getGBC(
                        3,
                        1,
                        1,
                        1,
                        0.0,
                        1.0,
                        GridBagConstraints.NONE,
                        GridBagConstraints.CENTER,
                        new Insets(0, 0, 4, 0)));

        ListSelectionListener selectionListener = e -> updateButtonStates();
        sourceList.addListSelectionListener(selectionListener);
        chainList.addListSelectionListener(selectionListener);
    }

    void loadSourceCatalog() {
        sourceModel.clear();
        sourceModel.addAll(ScriptChainPlanSupport.sourceCatalog(job));
        updateButtonStates();
    }

    @Override
    public void setEnabled(boolean enabled) {
        super.setEnabled(enabled);
        sourceList.setEnabled(enabled);
        chainList.setEnabled(enabled);
        updateButtonStates();
    }

    private void buildTransferButtons() {
        Dimension buttonSize = DisplayUtils.getScaledDimension(52, 26);
        transferButtons[0] =
                transferButton(">", buttonSize, TRANSFER_ADD_TOOLTIP, e -> moveSelectedToChain());
        transferButtons[1] =
                transferButton(">>", buttonSize, TRANSFER_ADD_ALL_TOOLTIP, e -> moveAllToChain());
        transferButtons[2] =
                transferButton(
                        "<", buttonSize, TRANSFER_REMOVE_TOOLTIP, e -> removeSelectedFromChain());
        transferButtons[3] =
                transferButton("<<", buttonSize, TRANSFER_CLEAR_TOOLTIP, e -> clearChain());
    }

    private void buildReorderButtons() {
        reorderButtons[0] =
                createReorderButton(
                        "multiple.options.panel.ordered.move.top.button", e -> reorderSelection(0));
        reorderButtons[1] =
                createReorderButton(
                        "multiple.options.panel.ordered.move.up.button",
                        e -> {
                            int index = chainList.getMinSelectionIndex();
                            reorderSelection(index - 1);
                        });
        reorderButtons[2] =
                createReorderButton(
                        "multiple.options.panel.ordered.move.down.button",
                        e -> {
                            int index = chainList.getMinSelectionIndex();
                            reorderSelection(index + 1);
                        });
        reorderButtons[3] =
                createReorderButton(
                        "multiple.options.panel.ordered.move.bottom.button",
                        e -> reorderSelection(chainModel.getSize() - 1));
    }

    private static JPanel verticalButtonPanel(JButton[] buttons, boolean stretchHorizontal) {
        JPanel panel = new JPanel(new GridBagLayout());
        for (int i = 0; i < buttons.length; i++) {
            panel.add(
                    buttons[i],
                    LayoutHelper.getGBC(
                            0,
                            i,
                            1,
                            stretchHorizontal ? 1.0 : 0.0,
                            0.0,
                            stretchHorizontal
                                    ? GridBagConstraints.HORIZONTAL
                                    : GridBagConstraints.NONE,
                            new Insets(2, 2, 2, 2)));
        }
        return panel;
    }

    private static JButton transferButton(
            String label, Dimension size, String tooltipKey, ActionListener listener) {
        JButton button = new JButton(label);
        button.setPreferredSize(size);
        button.setToolTipText(Constant.messages.getString(tooltipKey));
        button.addActionListener(listener);
        return button;
    }

    private static JButton createReorderButton(String messageKeyPrefix, ActionListener listener) {
        JButton button = new JButton(Constant.messages.getString(messageKeyPrefix + ".label"));
        button.setToolTipText(Constant.messages.getString(messageKeyPrefix + ".tooltip"));
        button.addActionListener(listener);
        return button;
    }

    private void moveSelectedToChain() {
        for (int index : sourceList.getSelectedIndices()) {
            chainModel.addElement(sourceModel.getElementAt(index));
        }
        updateButtonStates();
    }

    private void moveAllToChain() {
        for (int i = 0; i < sourceModel.getSize(); i++) {
            chainModel.addElement(sourceModel.getElementAt(i));
        }
        updateButtonStates();
    }

    private void removeSelectedFromChain() {
        int[] selected = chainList.getSelectedIndices();
        if (selected.length == 0) {
            return;
        }
        int[] sorted = selected.clone();
        Arrays.sort(sorted);
        for (int i = sorted.length - 1; i >= 0; i--) {
            chainModel.remove(sorted[i]);
        }
        updateButtonStates();
    }

    private void clearChain() {
        Window parent = SwingUtilities.getWindowAncestor(this);
        if (JOptionPane.OK_OPTION
                != View.getSingleton()
                        .showConfirmDialog(
                                parent, Constant.messages.getString(CLEAR_ALL_CONFIRM))) {
            return;
        }
        chainModel.clear();
        updateButtonStates();
    }

    private void reorderSelection(int to) {
        if (chainList.getSelectedIndices().length != 1) {
            return;
        }
        int index = chainList.getMinSelectionIndex();
        if (index < 0) {
            return;
        }
        int newIndex = moveTo(chainModel, index, to);
        if (newIndex >= 0 && newIndex < chainModel.getSize()) {
            chainList.setSelectionInterval(newIndex, newIndex);
        }
        updateButtonStates();
    }

    private static int moveTo(DefaultListModel<String> model, int from, int to) {
        if (from < 0 || from >= model.size() || to < 0 || to >= model.size()) {
            return from;
        }
        model.add(to, model.remove(from));
        return to;
    }

    private void updateButtonStates() {
        if (!isEnabled()) {
            setButtonsEnabled(transferButtons, false);
            setButtonsEnabled(reorderButtons, false);
            return;
        }
        transferButtons[0].setEnabled(!sourceList.isSelectionEmpty());
        transferButtons[1].setEnabled(sourceModel.getSize() > 0);
        transferButtons[2].setEnabled(!chainList.isSelectionEmpty());
        transferButtons[3].setEnabled(chainModel.getSize() > 0);

        int selectedIndex = chainList.getMinSelectionIndex();
        boolean hasSingleSelection =
                chainList.getSelectedIndices().length == 1 && selectedIndex >= 0;
        reorderButtons[0].setEnabled(hasSingleSelection && selectedIndex > 0);
        reorderButtons[1].setEnabled(hasSingleSelection && selectedIndex > 0);
        reorderButtons[2].setEnabled(
                hasSingleSelection && selectedIndex < chainModel.getSize() - 1);
        reorderButtons[3].setEnabled(
                hasSingleSelection && selectedIndex < chainModel.getSize() - 1);
    }

    private static void setButtonsEnabled(JButton[] buttons, boolean enabled) {
        Arrays.stream(buttons).forEach(button -> button.setEnabled(enabled));
    }
}
