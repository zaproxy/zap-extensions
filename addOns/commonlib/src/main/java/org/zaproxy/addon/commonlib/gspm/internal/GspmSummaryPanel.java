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
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;
import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.RowSorter;
import javax.swing.SortOrder;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.view.AbstractParamPanel;
import org.zaproxy.addon.commonlib.gspm.GspmPolicy;
import org.zaproxy.addon.commonlib.gspm.GspmRegistry;
import org.zaproxy.addon.commonlib.gspm.GspmRule;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.utils.ZapHtmlLabel;
import org.zaproxy.zap.utils.ZapLabel;

/**
 * Panel for the GSPM dialog's "Summary" tree node — the root of the tree when editing an actual
 * policy (see {@link GspmDialog}). Shows the policy's name (editable, unless it's the default
 * policy) and file location, an explanatory note, a live count, and a read-only table of every
 * currently enabled rule with its effective threshold, strength, and the rule set responsible for
 * that threshold (see {@link GspmEnabledRulesTableModel}).
 *
 * <p>{@link GspmDialog#validateParam()}/{@link GspmDialog#saveParam()} read the policy name back
 * via {@link #getPolicyNameText()}.
 *
 * @since 1.45.0
 */
@SuppressWarnings("serial")
class GspmSummaryPanel extends AbstractParamPanel {

    private static final long serialVersionUID = 1L;

    private static final int[] COL_WIDTHS = {260, 90, 90, 220};

    private final GspmPolicy policy;
    private final boolean newPolicy;
    private final Supplier<List<GspmRule>> rulesSupplier;
    private final GspmEnabledRulesTableModel tableModel;
    private final JTable table;
    private final JLabel countLabel = new JLabel();
    private JTextField policyNameField;

    /**
     * @param newPolicy {@code true} if {@code policy} was just created and has never been shown to
     *     the user under a real name yet — the name field then starts blank (instead of showing
     *     {@code policy}'s placeholder registration name), prompting the user to choose one.
     */
    GspmSummaryPanel(
            String displayName,
            GspmPolicy policy,
            Supplier<List<GspmRule>> rulesSupplier,
            boolean newPolicy) {
        this.policy = policy;
        this.newPolicy = newPolicy;
        this.rulesSupplier = rulesSupplier;
        setName(displayName);
        setLayout(new BorderLayout(0, 4));

        JPanel north = new JPanel(new BorderLayout(0, 4));
        north.add(buildPolicyInfoPanel(), BorderLayout.NORTH);

        JPanel notePanel = new JPanel(new BorderLayout(0, 2));
        notePanel.add(
                new ZapHtmlLabel(
                        "<html>"
                                + Constant.messages.getString("commonlib.gspm.dialog.summary.note")
                                + "</html>"),
                BorderLayout.NORTH);
        notePanel.add(countLabel, BorderLayout.SOUTH);
        north.add(notePanel, BorderLayout.SOUTH);
        add(north, BorderLayout.NORTH);

        tableModel = new GspmEnabledRulesTableModel(policy);
        table = buildTable();
        add(new JScrollPane(table), BorderLayout.CENTER);
    }

    @Override
    public void initParam(Object obj) {
        // no-op
    }

    @Override
    public void saveParam(Object obj) throws Exception {
        // no-op — the policy name is read directly via getPolicyNameText() by GspmDialog, and
        // everything else here is a read-only report
    }

    @Override
    public void onShow() {
        refresh();
    }

    /** Returns the current text of the (possibly just-edited) policy name field. */
    String getPolicyNameText() {
        return policyNameField.getText();
    }

    private void refresh() {
        List<GspmRule> enabled = new ArrayList<>();
        for (GspmRule rule : rulesSupplier.get()) {
            if (rule.getAlertThreshold() != AlertThreshold.OFF) {
                enabled.add(rule);
            }
        }
        tableModel.setRules(enabled);
        countLabel.setText(
                Constant.messages.getString("commonlib.gspm.dialog.summary.count", enabled.size()));
    }

    private JPanel buildPolicyInfoPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(4, 4, 0, 4));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(2, 4, 2, 4);
        gbc.anchor = GridBagConstraints.WEST;

        gbc.gridx = 0;
        gbc.gridy = 0;
        JLabel nameLabel =
                new JLabel(Constant.messages.getString("commonlib.gspm.dialog.policy.name"));
        panel.add(nameLabel, gbc);

        policyNameField = new JTextField(newPolicy ? "" : policy.getName(), 30);
        policyNameField.setEditable(!GspmRegistry.getDefaultPolicyName().equals(policy.getName()));
        nameLabel.setLabelFor(policyNameField);
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        panel.add(policyNameField, gbc);

        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.weightx = 0.0;
        gbc.fill = GridBagConstraints.NONE;
        // Label text stays "File:" even though the value shown is just the directory — the file
        // name itself is already implied by the policy name shown right above.
        JLabel fileNameLabel =
                new JLabel(Constant.messages.getString("commonlib.gspm.dialog.policy.file"));
        panel.add(fileNameLabel, gbc);

        ZapLabel fileLabel = new ZapLabel(policyDirectory());
        fileNameLabel.setLabelFor(fileLabel);
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        panel.add(fileLabel, gbc);

        return panel;
    }

    /**
     * Returns the directory the policy's file is (or will be) saved in — {@link
     * GspmPolicy#getFile()}'s parent if it's been saved/loaded already, otherwise {@link
     * Constant#getPoliciesDir()}.
     */
    private String policyDirectory() {
        File file = policy.getFile();
        File dir = file != null ? file.getParentFile() : null;
        return (dir != null ? dir : Constant.getPoliciesDir()).getAbsolutePath();
    }

    private JTable buildTable() {
        JTable t = new JTable(tableModel);
        t.setRowHeight(DisplayUtils.getScaledSize(18));
        t.setIntercellSpacing(new Dimension(1, 1));
        t.setAutoCreateRowSorter(true);
        t.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        List<RowSorter.SortKey> sortKeys = new ArrayList<>(1);
        sortKeys.add(
                new RowSorter.SortKey(GspmEnabledRulesTableModel.COL_NAME, SortOrder.ASCENDING));
        t.getRowSorter().setSortKeys(sortKeys);

        for (int i = 0; i < COL_WIDTHS.length; i++) {
            t.getColumnModel().getColumn(i).setPreferredWidth(COL_WIDTHS[i]);
        }
        return t;
    }
}
