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

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import javax.swing.table.AbstractTableModel;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.zaproxy.addon.commonlib.gspm.GspmPolicy;
import org.zaproxy.addon.commonlib.gspm.GspmRule;
import org.zaproxy.addon.commonlib.gspm.GspmRuleSet;

/**
 * Read-only table model for the GSPM dialog's "Enabled Rules" tree node: one row per currently
 * enabled {@link GspmRule}, showing its effective threshold, strength, and the {@link GspmRuleSet}
 * responsible for its effective threshold (see {@link GspmPolicy#getEffectiveThresholdRuleSet}) —
 * i.e. the rule set that makes it enabled rather than {@code OFF}.
 *
 * <p>Purely a derived report of current policy state, so unlike {@link GspmRuleTableModel} nothing
 * here is editable.
 *
 * @since 1.45.0
 */
@SuppressWarnings("serial")
public class GspmEnabledRulesTableModel extends AbstractTableModel {

    private static final long serialVersionUID = 1L;

    static final int COL_NAME = 0;
    static final int COL_THRESHOLD = 1;
    static final int COL_STRENGTH = 2;
    static final int COL_RULESET = 3;
    static final int COL_COUNT = 4;

    private final GspmPolicy policy;
    private List<GspmRule> rules = new ArrayList<>();

    GspmEnabledRulesTableModel(GspmPolicy policy) {
        this.policy = policy;
    }

    /** Replaces the displayed rules and fires a full table-data-changed event. */
    void setRules(List<GspmRule> newRules) {
        this.rules = new ArrayList<>(newRules);
        fireTableDataChanged();
    }

    @Override
    public int getRowCount() {
        return rules.size();
    }

    @Override
    public int getColumnCount() {
        return COL_COUNT;
    }

    @Override
    public String getColumnName(int col) {
        return switch (col) {
            case COL_NAME -> Constant.messages.getString("commonlib.gspm.dialog.table.col.name");
            case COL_THRESHOLD ->
                    Constant.messages.getString("commonlib.gspm.dialog.table.col.threshold");
            case COL_STRENGTH ->
                    Constant.messages.getString("commonlib.gspm.dialog.table.col.strength");
            case COL_RULESET ->
                    Constant.messages.getString("commonlib.gspm.dialog.table.col.ruleset");
            default -> "";
        };
    }

    @Override
    public Class<?> getColumnClass(int col) {
        return String.class;
    }

    @Override
    public boolean isCellEditable(int row, int col) {
        return false;
    }

    @Override
    public Object getValueAt(int row, int col) {
        GspmRule rule = rules.get(row);
        return switch (col) {
            case COL_NAME -> rule.getName();
            case COL_THRESHOLD ->
                    Constant.messages.getString(
                            "ascan.policy.level."
                                    + rule.getAlertThreshold().name().toLowerCase(Locale.ROOT));
            case COL_STRENGTH -> {
                AttackStrength s = rule.getAttackStrength();
                yield s != null
                        ? Constant.messages.getString(
                                "ascan.policy.level." + s.name().toLowerCase(Locale.ROOT))
                        : Constant.messages.getString("commonlib.gspm.rule.strength.na");
            }
            case COL_RULESET -> ruleSetName(rule);
            default -> "";
        };
    }

    /**
     * Returns the display name of whichever rule set is responsible for {@code rule} being enabled:
     * the one that sets its effective threshold if any does, otherwise the policy's catch-all (a
     * rule can be enabled purely by its own inherent default, with no rule set explicitly
     * overriding its threshold at all — the catch-all is still conceptually "why" it's enabled
     * under this policy). If the policy has no catch-all either — e.g. one that disables everything
     * via a category-scoped {@code OFF} (not a real catch-all) and re-enables specific rules by
     * explicit id, leaving every other tool/category completely untouched — the rule is enabled
     * purely by its own built-in default, with nothing in the policy responsible for that at all,
     * so a fixed "Policy Default" label is shown instead of leaving the cell blank.
     */
    private String ruleSetName(GspmRule rule) {
        GspmRuleSet rs =
                policy.getEffectiveThresholdRuleSet(rule).orElseGet(policy::findCatchAllRuleSet);
        return rs != null
                ? GspmRuleSetTableModel.displayName(rs)
                : Constant.messages.getString("commonlib.gspm.ruleset.name.policydefault");
    }
}
