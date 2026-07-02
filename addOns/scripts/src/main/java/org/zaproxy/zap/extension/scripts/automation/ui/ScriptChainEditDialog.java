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
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Window;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.BiFunction;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.ListSelectionModel;
import javax.swing.border.EmptyBorder;
import javax.swing.event.ListSelectionListener;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.AbstractDialog;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.scripts.automation.ScriptJob;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.utils.ZapHtmlLabel;
import org.zaproxy.zap.view.LayoutHelper;

@SuppressWarnings("serial")
class ScriptChainEditDialog extends AbstractDialog {

    private static final String TITLE = "scripts.automation.dialog.chain.edit.title";
    private static final String TITLE_AVAILABLE = "scripts.automation.dialog.chain.available";
    private static final String TITLE_SELECTED = "scripts.automation.dialog.chain.selected";
    private static final String CLEAR_ALL_CONFIRM =
            "scripts.automation.dialog.chain.clearAllConfirm";

    private final List<String> chain;
    private final DefaultListModel<String> sourceModel = new DefaultListModel<>();
    private final DefaultListModel<String> chainModel = new DefaultListModel<>();
    private final JList<String> sourceList = new JList<>(sourceModel);
    private final JList<String> chainList = new JList<>(chainModel);
    private final JButton[] transferButtons = new JButton[4];
    private final JButton[] reorderButtons = new JButton[4];

    private JButton okButton;

    private List<String> result;

    private ScriptChainEditDialog(Window parent, ScriptJob job, List<String> initialChain) {
        super(parent, true);
        setTitle(Constant.messages.getString(TITLE));
        chain = new ArrayList<>(initialChain);
        sourceModel.addAll(ScriptChainPlanSupport.sourceCatalog(job));
        refreshChainModel();

        sourceList.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        chainList.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);

        ListSelectionListener selectionListener = e -> updateButtonStates();
        sourceList.addListSelectionListener(selectionListener);
        chainList.addListSelectionListener(selectionListener);

        setContentPane(buildContentPanel());
        getRootPane().setDefaultButton(okButton);
        pack();
        setSize(DisplayUtils.getScaledDimension(640, 420));
    }

    static List<String> showDialog(Window parent, ScriptJob job, List<String> initialChain) {
        ScriptChainEditDialog dialog =
                new ScriptChainEditDialog(
                        parent, job, initialChain != null ? initialChain : List.of());
        dialog.setVisible(true);
        return dialog.result;
    }

    private JPanel buildContentPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(new EmptyBorder(8, 8, 8, 8));

        panel.add(
                new ZapHtmlLabel(Constant.messages.getString(TITLE_AVAILABLE)),
                LayoutHelper.getGBC(
                        0, 0, 1, 0.0, 0.0, GridBagConstraints.WEST, new Insets(0, 0, 4, 4)));
        panel.add(
                new ZapHtmlLabel(Constant.messages.getString(TITLE_SELECTED)),
                LayoutHelper.getGBC(
                        2, 0, 1, 0.0, 0.0, GridBagConstraints.WEST, new Insets(0, 0, 4, 4)));

        JScrollPane sourceScrollPane = new JScrollPane(sourceList);
        sourceScrollPane.setPreferredSize(DisplayUtils.getScaledDimension(220, 240));
        panel.add(
                sourceScrollPane,
                LayoutHelper.getGBC(
                        0, 1, 1, 1.0, 1.0, GridBagConstraints.BOTH, new Insets(0, 0, 4, 4)));

        panel.add(
                buildTransferButtonsPanel(),
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
        panel.add(
                chainScrollPane,
                LayoutHelper.getGBC(
                        2, 1, 1, 1.0, 1.0, GridBagConstraints.BOTH, new Insets(0, 0, 4, 4)));

        panel.add(
                buildReorderButtonsPanel(),
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

        panel.add(
                buildOkCancelPanel(),
                LayoutHelper.getGBC(
                        0,
                        2,
                        4,
                        1,
                        1.0,
                        0.0,
                        GridBagConstraints.HORIZONTAL,
                        GridBagConstraints.EAST,
                        new Insets(4, 0, 0, 0)));

        updateButtonStates();
        return panel;
    }

    private JPanel buildTransferButtonsPanel() {
        JPanel transferPanel = new JPanel(new GridBagLayout());
        Dimension buttonSize = DisplayUtils.getScaledDimension(52, 26);

        transferButtons[0] = createTransferButton(">", buttonSize, e -> moveSelectedToChain());
        transferButtons[1] = createTransferButton(">>", buttonSize, e -> moveAllToChain());
        transferButtons[2] = createTransferButton("<", buttonSize, e -> removeSelectedFromChain());
        transferButtons[3] = createTransferButton("<<", buttonSize, e -> clearChain());

        for (int i = 0; i < transferButtons.length; i++) {
            transferPanel.add(
                    transferButtons[i],
                    LayoutHelper.getGBC(
                            0,
                            i,
                            1,
                            1.0,
                            0.0,
                            GridBagConstraints.HORIZONTAL,
                            new Insets(2, 2, 2, 2)));
        }

        return transferPanel;
    }

    private JPanel buildReorderButtonsPanel() {
        JPanel reorderPanel = new JPanel(new GridBagLayout());

        reorderButtons[0] =
                createReorderButton(
                        "multiple.options.panel.ordered.move.top.button",
                        e -> reorderSelected((list, i) -> moveTo(list, i, 0)));
        reorderButtons[1] =
                createReorderButton(
                        "multiple.options.panel.ordered.move.up.button",
                        e -> reorderSelected((list, i) -> moveTo(list, i, i - 1)));
        reorderButtons[2] =
                createReorderButton(
                        "multiple.options.panel.ordered.move.down.button",
                        e -> reorderSelected((list, i) -> moveTo(list, i, i + 1)));
        reorderButtons[3] =
                createReorderButton(
                        "multiple.options.panel.ordered.move.bottom.button",
                        e -> reorderSelected((list, i) -> moveTo(list, i, list.size() - 1)));

        for (int i = 0; i < reorderButtons.length; i++) {
            reorderPanel.add(
                    reorderButtons[i],
                    LayoutHelper.getGBC(
                            0, i, 1, 0.0, 0.0, GridBagConstraints.NONE, new Insets(2, 2, 2, 2)));
        }

        return reorderPanel;
    }

    private JPanel buildOkCancelPanel() {
        JPanel buttonGroup = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 0));

        okButton = new JButton(Constant.messages.getString("all.button.ok"));
        okButton.addActionListener(
                e -> {
                    result = new ArrayList<>(chain);
                    dispose();
                });

        JButton cancelButton = new JButton(Constant.messages.getString("all.button.cancel"));
        cancelButton.addActionListener(
                e -> {
                    result = null;
                    dispose();
                });

        buttonGroup.add(okButton);
        buttonGroup.add(cancelButton);
        return buttonGroup;
    }

    private static JButton createTransferButton(
            String label, Dimension size, ActionListener listener) {
        JButton button = new JButton(label);
        button.setPreferredSize(size);
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
            if (index >= 0 && index < sourceModel.getSize()) {
                chain.add(sourceModel.getElementAt(index));
            }
        }
        refreshUi();
    }

    private void moveAllToChain() {
        for (int i = 0; i < sourceModel.getSize(); i++) {
            chain.add(sourceModel.getElementAt(i));
        }
        refreshUi();
    }

    private void removeSelectedFromChain() {
        int[] selected = chainList.getSelectedIndices();
        if (selected.length == 0) {
            return;
        }
        int[] sorted = selected.clone();
        Arrays.sort(sorted);
        for (int i = sorted.length - 1; i >= 0; i--) {
            int index = sorted[i];
            if (index >= 0 && index < chain.size()) {
                chain.remove(index);
            }
        }
        refreshUi();
    }

    private void clearChain() {
        if (JOptionPane.OK_OPTION
                != View.getSingleton()
                        .showConfirmDialog(this, Constant.messages.getString(CLEAR_ALL_CONFIRM))) {
            return;
        }
        chain.clear();
        refreshUi();
    }

    private void reorderSelected(BiFunction<List<String>, Integer, Integer> operation) {
        if (chainList.getSelectedIndices().length != 1) {
            return;
        }
        int index = chainList.getMinSelectionIndex();
        if (index < 0) {
            return;
        }
        int newIndex = operation.apply(chain, index);
        chainList.setSelectionInterval(newIndex, newIndex);
        refreshUi();
    }

    private static int moveTo(List<String> items, int from, int to) {
        if (from < 0 || from >= items.size() || to < 0 || to >= items.size()) {
            return from;
        }
        items.add(to, items.remove(from));
        return to;
    }

    private void refreshUi() {
        refreshChainModel();
        updateButtonStates();
    }

    private void refreshChainModel() {
        chainModel.clear();
        chainModel.addAll(chain);
    }

    private void updateButtonStates() {
        transferButtons[0].setEnabled(!sourceList.isSelectionEmpty());
        transferButtons[1].setEnabled(sourceModel.getSize() > 0);
        transferButtons[2].setEnabled(!chainList.isSelectionEmpty());
        transferButtons[3].setEnabled(!chain.isEmpty());

        int selectedIndex = chainList.getMinSelectionIndex();
        boolean hasSingleSelection =
                chainList.getSelectedIndices().length == 1 && selectedIndex >= 0;
        reorderButtons[0].setEnabled(hasSingleSelection && selectedIndex > 0);
        reorderButtons[1].setEnabled(hasSingleSelection && selectedIndex > 0);
        reorderButtons[2].setEnabled(hasSingleSelection && selectedIndex < chain.size() - 1);
        reorderButtons[3].setEnabled(hasSingleSelection && selectedIndex < chain.size() - 1);
    }
}
