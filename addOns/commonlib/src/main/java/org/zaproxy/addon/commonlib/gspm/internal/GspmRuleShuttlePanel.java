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
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
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
import org.zaproxy.addon.commonlib.gspm.GspmRule;
import org.zaproxy.addon.commonlib.gspm.GspmRuleRef;
import org.zaproxy.addon.commonlib.gspm.GspmRuleSet;

/**
 * A two-pane "shuttle" picker for choosing which rules an explicit {@link GspmRuleSet#getRules()}
 * list references, used by {@link GspmRuleSetDialog}'s "Rules" tab.
 *
 * <p>Every known rule is listed on the left (filterable by name/tool/id); the currently included
 * ones are listed separately on the right. Moving rules between the two with the Add/Remove buttons
 * (or a double-click) keeps it obvious at a glance which rules are, and aren't, included — unlike a
 * single multi-select list, where an included rule can be scrolled out of view and easily missed
 * among hundreds of candidates.
 *
 * <p>A rule id already referenced by the rule set but no longer known (e.g. its add-on was
 * uninstalled, or a script was removed) is still shown — on the right only, using the name last
 * recorded for it — so it isn't silently dropped by opening and saving this dialog.
 *
 * @since 1.45.0
 */
@SuppressWarnings("serial")
class GspmRuleShuttlePanel extends JPanel {

    private static final long serialVersionUID = 1L;

    /** One selectable entry: a currently known rule, or a stale reference to one that isn't. */
    private record Item(int id, String name, String tool, boolean stale) {

        String label() {
            String base = tool == null || tool.isEmpty() ? name : name + " (" + tool + ")";
            return stale
                    ? Constant.messages.getString("commonlib.gspm.ruleset.dialog.rules.stale", base)
                    : base;
        }

        String filterText() {
            return label().toLowerCase(Locale.ROOT) + " " + id;
        }

        @Override
        public String toString() {
            // JList's default renderer displays each element via toString().
            return label();
        }
    }

    private final List<Item> allItems;
    private final Set<Integer> includedIds;
    private final DefaultListModel<Item> availableModel = new DefaultListModel<>();
    private final DefaultListModel<Item> includedModel = new DefaultListModel<>();
    private final JList<Item> availableList = new JList<>(availableModel);
    private final JList<Item> includedList = new JList<>(includedModel);
    private final JTextField filterField = new JTextField();
    private final JLabel includedTitle = new JLabel();

    GspmRuleShuttlePanel(List<GspmRule> availableRules, List<GspmRuleRef> initiallyIncluded) {
        Map<Integer, Item> byId = new LinkedHashMap<>();
        for (GspmRule rule : availableRules) {
            byId.put(rule.getId(), new Item(rule.getId(), rule.getName(), rule.getTool(), false));
        }
        this.includedIds = new LinkedHashSet<>();
        for (GspmRuleRef ref : initiallyIncluded) {
            byId.putIfAbsent(ref.getId(), new Item(ref.getId(), ref.getName(), "", true));
            includedIds.add(ref.getId());
        }
        this.allItems = new ArrayList<>(byId.values());
        this.allItems.sort(Comparator.comparing(i -> i.label().toLowerCase(Locale.ROOT)));

        setLayout(new BorderLayout(2, 4));

        JPanel filterRow = new JPanel(new BorderLayout(4, 0));
        filterRow.add(
                new JLabel(
                        Constant.messages.getString("commonlib.gspm.ruleset.dialog.rules.filter")),
                BorderLayout.WEST);
        filterRow.add(filterField, BorderLayout.CENTER);
        add(filterRow, BorderLayout.NORTH);
        filterField
                .getDocument()
                .addDocumentListener(
                        new DocumentListener() {
                            @Override
                            public void insertUpdate(DocumentEvent e) {
                                refresh();
                            }

                            @Override
                            public void removeUpdate(DocumentEvent e) {
                                refresh();
                            }

                            @Override
                            public void changedUpdate(DocumentEvent e) {
                                refresh();
                            }
                        });

        availableList.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        availableList.setVisibleRowCount(10);
        availableList.addMouseListener(doubleClickListener(this::addSelected));

        includedList.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        includedList.setVisibleRowCount(10);
        includedList.addMouseListener(doubleClickListener(this::removeSelected));

        JPanel center = new JPanel(new GridBagLayout());
        center.add(titledScrollPane(availableTitleLabel(), availableList), listConstraints(0));
        center.add(transferButtonsPanel(), buttonColumnConstraints());
        center.add(titledScrollPane(includedTitle, includedList), listConstraints(2));
        add(center, BorderLayout.CENTER);

        refresh();
    }

    private static JLabel availableTitleLabel() {
        return new JLabel(
                Constant.messages.getString("commonlib.gspm.ruleset.dialog.rules.available"));
    }

    private static JPanel titledScrollPane(JLabel title, JList<Item> list) {
        JPanel panel = new JPanel(new BorderLayout(0, 2));
        panel.add(title, BorderLayout.NORTH);
        panel.add(new JScrollPane(list), BorderLayout.CENTER);
        return panel;
    }

    private static GridBagConstraints listConstraints(int gridx) {
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = gridx;
        gbc.gridy = 0;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.insets = new Insets(0, 2, 0, 2);
        return gbc;
    }

    private static GridBagConstraints buttonColumnConstraints() {
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 1;
        gbc.gridy = 0;
        gbc.weightx = 0;
        gbc.weighty = 0;
        gbc.anchor = GridBagConstraints.CENTER;
        gbc.insets = new Insets(0, 2, 0, 2);
        return gbc;
    }

    private JPanel transferButtonsPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        int row = 0;

        // Compact arrow glyphs rather than full-width text buttons (e.g. "Add All >>") so the
        // button column doesn't eat into the space the two rule lists need; the action is instead
        // given as a tooltip.
        panel.add(
                arrowButton(">", "commonlib.gspm.ruleset.dialog.rules.add", this::addSelected),
                buttonRowConstraints(row++));
        panel.add(
                arrowButton(
                        ">>", "commonlib.gspm.ruleset.dialog.rules.addall", this::addAllVisible),
                buttonRowConstraints(row++));
        panel.add(
                arrowButton(
                        "<", "commonlib.gspm.ruleset.dialog.rules.remove", this::removeSelected),
                buttonRowConstraints(row++));
        panel.add(
                arrowButton(
                        "<<",
                        "commonlib.gspm.ruleset.dialog.rules.removeall",
                        this::removeAllIncluded),
                buttonRowConstraints(row++));

        return panel;
    }

    private static JButton arrowButton(String glyph, String tooltipKey, Runnable action) {
        JButton button = new JButton(glyph);
        button.setToolTipText(Constant.messages.getString(tooltipKey));
        button.addActionListener(e -> action.run());
        return button;
    }

    private static GridBagConstraints buttonRowConstraints(int row) {
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.fill = GridBagConstraints.NONE;
        gbc.anchor = GridBagConstraints.CENTER;
        gbc.insets = new Insets(2, 2, 2, 2);
        return gbc;
    }

    private static MouseAdapter doubleClickListener(Runnable action) {
        return new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                if (e.getClickCount() >= 2) {
                    action.run();
                }
            }
        };
    }

    private void addSelected() {
        for (Item item : availableList.getSelectedValuesList()) {
            includedIds.add(item.id());
        }
        refresh();
    }

    private void addAllVisible() {
        for (int i = 0; i < availableModel.getSize(); i++) {
            includedIds.add(availableModel.getElementAt(i).id());
        }
        refresh();
    }

    private void removeSelected() {
        for (Item item : includedList.getSelectedValuesList()) {
            includedIds.remove(item.id());
        }
        refresh();
    }

    private void removeAllIncluded() {
        includedIds.clear();
        refresh();
    }

    /**
     * Rebuilds both list models from {@link #allItems}/{@link #includedIds} and the filter text.
     */
    private void refresh() {
        String filter = filterField.getText().trim().toLowerCase(Locale.ROOT);
        availableModel.clear();
        includedModel.clear();
        for (Item item : allItems) {
            if (includedIds.contains(item.id())) {
                includedModel.addElement(item);
            } else if (filter.isEmpty() || item.filterText().contains(filter)) {
                availableModel.addElement(item);
            }
        }
        includedTitle.setText(
                Constant.messages.getString(
                        "commonlib.gspm.ruleset.dialog.rules.included", includedIds.size()));
    }

    /**
     * Returns the currently included rules, in display (name) order, each carrying the referenced
     * rule's current name — or, for a stale reference, the name it was last known by.
     */
    List<GspmRuleRef> getSelectedRuleRefs() {
        List<GspmRuleRef> result = new ArrayList<>();
        for (int i = 0; i < includedModel.getSize(); i++) {
            Item item = includedModel.getElementAt(i);
            result.add(new GspmRuleRef(item.id(), item.name()));
        }
        return result;
    }
}
