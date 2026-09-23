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
package org.zaproxy.addon.commonlib.gspm.internal;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Container;
import java.awt.FlowLayout;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import org.parosproxy.paros.Constant;

/**
 * A filterable, multi-select picker for choosing from a fixed set of known alert tags, used by
 * {@link GspmRuleSetDialog} in place of free-text tag entry.
 *
 * <p>Typing in the filter field narrows the visible list to tags containing the typed text (a plain
 * substring match, no regex); "Select Visible" then selects every currently-filtered tag in one
 * action — e.g. typing {@code OWASP_2021_} and clicking it selects the whole {@code OWASP_2021_*}
 * family without picking each one individually. Standard {@link JList} multi-selection (click,
 * shift-click for a range, ctrl/cmd-click to toggle) also works as usual on whatever is currently
 * visible. Selections made while a tag is hidden by the filter are preserved — only
 * currently-visible rows are ever synced against the selection set, so narrowing or widening the
 * filter never drops a selection made earlier under a different filter.
 *
 * @since 1.45.0
 */
@SuppressWarnings("serial")
class GspmTagChooserPanel extends JPanel {

    private static final long serialVersionUID = 1L;

    private final List<String> allTags;
    private final Set<String> selected;
    private final DefaultListModel<String> listModel = new DefaultListModel<>();
    private final JList<String> list = new JList<>(listModel);
    private final JTextField filterField = new JTextField();
    private final JLabel countLabel = new JLabel();

    GspmTagChooserPanel(List<String> availableTags, List<String> initiallySelected) {
        this.allTags = new ArrayList<>(availableTags);
        this.selected = new LinkedHashSet<>(initiallySelected);

        setLayout(new BorderLayout(2, 2));

        JPanel filterRow = new JPanel(new BorderLayout(4, 0));
        filterRow.add(
                new JLabel(
                        Constant.messages.getString("commonlib.gspm.ruleset.dialog.tags.filter")),
                BorderLayout.WEST);
        filterRow.add(filterField, BorderLayout.CENTER);
        add(filterRow, BorderLayout.NORTH);
        filterField
                .getDocument()
                .addDocumentListener(
                        new DocumentListener() {
                            @Override
                            public void insertUpdate(DocumentEvent e) {
                                refreshFilter();
                            }

                            @Override
                            public void removeUpdate(DocumentEvent e) {
                                refreshFilter();
                            }

                            @Override
                            public void changedUpdate(DocumentEvent e) {
                                refreshFilter();
                            }
                        });

        list.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        list.setVisibleRowCount(7);
        list.addListSelectionListener(
                e -> {
                    if (!e.getValueIsAdjusting()) {
                        syncSelectedFromVisible();
                    }
                });
        add(new JScrollPane(list), BorderLayout.CENTER);

        JPanel south = new JPanel(new BorderLayout());
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        JButton selectAll =
                new JButton(
                        Constant.messages.getString(
                                "commonlib.gspm.ruleset.dialog.tags.selectall"));
        selectAll.addActionListener(
                e -> {
                    if (!listModel.isEmpty()) {
                        list.setSelectionInterval(0, listModel.getSize() - 1);
                    }
                });
        buttons.add(selectAll);
        JButton clearAll =
                new JButton(
                        Constant.messages.getString("commonlib.gspm.ruleset.dialog.tags.clearall"));
        clearAll.addActionListener(e -> list.clearSelection());
        buttons.add(clearAll);
        south.add(buttons, BorderLayout.WEST);
        south.add(countLabel, BorderLayout.EAST);
        add(south, BorderLayout.SOUTH);

        refreshFilter();
    }

    /** Returns the currently selected tags, in their original {@code availableTags} order. */
    List<String> getSelectedTags() {
        List<String> result = new ArrayList<>();
        for (String tag : allTags) {
            if (selected.contains(tag)) {
                result.add(tag);
            }
        }
        return result;
    }

    @Override
    public void setEnabled(boolean enabled) {
        super.setEnabled(enabled);
        for (Component c : getComponents()) {
            setEnabledRecursive(c, enabled);
        }
    }

    private static void setEnabledRecursive(Component c, boolean enabled) {
        c.setEnabled(enabled);
        if (c instanceof Container container) {
            for (Component child : container.getComponents()) {
                setEnabledRecursive(child, enabled);
            }
        }
    }

    /** Rebuilds the visible list from the filter text, preserving selections made while hidden. */
    private void refreshFilter() {
        String filter = filterField.getText().trim().toLowerCase(Locale.ROOT);
        listModel.clear();
        for (String tag : allTags) {
            if (filter.isEmpty() || tag.toLowerCase(Locale.ROOT).contains(filter)) {
                listModel.addElement(tag);
            }
        }
        List<Integer> toSelect = new ArrayList<>();
        for (int i = 0; i < listModel.getSize(); i++) {
            if (selected.contains(listModel.getElementAt(i))) {
                toSelect.add(i);
            }
        }
        list.setSelectedIndices(toSelect.stream().mapToInt(Integer::intValue).toArray());
        updateCountLabel();
    }

    /** Syncs the selection set against only the rows currently visible in the (filtered) list. */
    private void syncSelectedFromVisible() {
        for (int i = 0; i < listModel.getSize(); i++) {
            String tag = listModel.getElementAt(i);
            if (list.isSelectedIndex(i)) {
                selected.add(tag);
            } else {
                selected.remove(tag);
            }
        }
        updateCountLabel();
    }

    private void updateCountLabel() {
        countLabel.setText(
                Constant.messages.getString(
                        "commonlib.gspm.ruleset.dialog.tags.selectedcount", selected.size()));
    }
}
