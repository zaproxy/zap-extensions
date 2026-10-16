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
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import javax.swing.table.AbstractTableModel;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.zaproxy.addon.commonlib.gspm.GspmRuleRef;
import org.zaproxy.addon.commonlib.gspm.GspmRuleSet;

/**
 * Table model for the GSPM "Rule Sets" panel, showing one row per {@link GspmRuleSet} in a policy,
 * in list order — which is also match-precedence order, since the last matching rule set wins (see
 * {@code GspmPolicy#getEffectiveThreshold/Strength}).
 *
 * <p>Columns: Name (falls back to a synthesized label for rule sets created implicitly by the
 * category/phase tree nodes, which don't set an explicit name), Match (read-only summary of what
 * the rule set matches), Threshold, Strength — the latter two editable via the same enum/i18n
 * round-trip used by {@link GspmRuleTableModel}.
 *
 * @since 1.45.0
 */
@SuppressWarnings("serial")
public class GspmRuleSetTableModel extends AbstractTableModel {

    private static final long serialVersionUID = 1L;

    static final int COL_NAME = 0;
    static final int COL_MATCH = 1;
    static final int COL_THRESHOLD = 2;
    static final int COL_STRENGTH = 3;
    static final int COL_COUNT = 4;

    private List<GspmRuleSet> ruleSets = new ArrayList<>();
    private Map<String, String> i18nToEnum;

    /** Replaces the displayed rule sets and fires a full table-data-changed event. */
    public void setRuleSets(List<GspmRuleSet> newRuleSets) {
        this.ruleSets = new ArrayList<>(newRuleSets);
        i18nToEnum = null;
        fireTableDataChanged();
    }

    List<GspmRuleSet> getRuleSets() {
        return ruleSets;
    }

    GspmRuleSet getRuleSet(int row) {
        return ruleSets.get(row);
    }

    @Override
    public int getRowCount() {
        return ruleSets.size();
    }

    @Override
    public int getColumnCount() {
        return COL_COUNT;
    }

    @Override
    public String getColumnName(int col) {
        return switch (col) {
            case COL_NAME ->
                    Constant.messages.getString("commonlib.gspm.dialog.rulesets.table.col.name");
            case COL_MATCH ->
                    Constant.messages.getString("commonlib.gspm.dialog.rulesets.table.col.match");
            case COL_THRESHOLD ->
                    Constant.messages.getString("commonlib.gspm.dialog.table.col.threshold");
            case COL_STRENGTH ->
                    Constant.messages.getString("commonlib.gspm.dialog.table.col.strength");
            default -> "";
        };
    }

    @Override
    public Class<?> getColumnClass(int col) {
        return String.class;
    }

    @Override
    public boolean isCellEditable(int row, int col) {
        return col == COL_THRESHOLD || col == COL_STRENGTH;
    }

    @Override
    public Object getValueAt(int row, int col) {
        GspmRuleSet rs = ruleSets.get(row);
        return switch (col) {
            case COL_NAME -> displayName(rs);
            case COL_MATCH -> matchSummary(rs);
            case COL_THRESHOLD -> thresholdToI18n(rs.getThresholdEnum());
            case COL_STRENGTH -> strengthToI18n(rs.getStrengthEnum());
            default -> "";
        };
    }

    @Override
    public void setValueAt(Object value, int row, int col) {
        GspmRuleSet rs = ruleSets.get(row);
        switch (col) {
            case COL_THRESHOLD -> {
                AlertThreshold t = i18nToThreshold((String) value);
                if (t != null) {
                    rs.setThresholdEnum(t);
                    fireTableCellUpdated(row, col);
                }
            }
            case COL_STRENGTH -> {
                AttackStrength s = i18nToStrength((String) value);
                if (s != null) {
                    rs.setStrengthEnum(s);
                    fireTableCellUpdated(row, col);
                }
            }
            default -> {
                // Name and Match are edited via the Add/Edit dialog, not inline
            }
        }
    }

    String thresholdToI18n(AlertThreshold t) {
        return Constant.messages.getString(
                "ascan.policy.level." + t.name().toLowerCase(Locale.ROOT));
    }

    String strengthToI18n(AttackStrength s) {
        return Constant.messages.getString(
                "ascan.policy.level." + s.name().toLowerCase(Locale.ROOT));
    }

    AlertThreshold i18nToThreshold(String s) {
        buildI18nMap();
        String enumName = i18nToEnum.get(s);
        return enumName != null ? AlertThreshold.valueOf(enumName) : null;
    }

    AttackStrength i18nToStrength(String s) {
        buildI18nMap();
        String enumName = i18nToEnum.get(s);
        return enumName != null ? AttackStrength.valueOf(enumName) : null;
    }

    private void buildI18nMap() {
        if (i18nToEnum != null) {
            return;
        }
        i18nToEnum = new HashMap<>();
        for (AlertThreshold t : AlertThreshold.values()) {
            i18nToEnum.put(thresholdToI18n(t), t.name());
        }
        for (AttackStrength s : AttackStrength.values()) {
            i18nToEnum.put(strengthToI18n(s), s.name());
        }
    }

    /**
     * Returns {@code rs}'s display name: its explicit {@link GspmRuleSet#getName()} if set, else a
     * synthesized label so rule sets created implicitly by the category/phase tree nodes (which
     * never set a name) stay legible in this table.
     */
    static String displayName(GspmRuleSet rs) {
        if (rs.getName() != null && !rs.getName().isBlank()) {
            return rs.getName();
        }
        List<GspmRuleRef> rules = rs.getRules();
        if (rules != null && rules.size() == 1) {
            return Constant.messages.getString(
                    "commonlib.gspm.ruleset.name.rule", rules.get(0).getName());
        }
        String category = rs.getCategory();
        if (category == null || category.equalsIgnoreCase(GspmRuleSet.ALL_CATEGORY)) {
            return Constant.messages.getString("commonlib.gspm.ruleset.name.catchall");
        }
        if (category.startsWith(GspmRuleSet.PHASE_PREFIX)) {
            return Constant.messages.getString(
                    "commonlib.gspm.ruleset.name.phase",
                    category.substring(GspmRuleSet.PHASE_PREFIX.length()));
        }
        return Constant.messages.getString("commonlib.gspm.ruleset.name.category", category);
    }

    /** Returns a short, read-only summary of what {@code rs} matches. */
    static String matchSummary(GspmRuleSet rs) {
        List<GspmRuleRef> rules = rs.getRules();
        if (rules != null && !rules.isEmpty()) {
            return rules.size() == 1
                    ? Constant.messages.getString(
                            "commonlib.gspm.dialog.rulesets.match.rule", rules.get(0).getName())
                    : Constant.messages.getString(
                            "commonlib.gspm.dialog.rulesets.match.rules", rules.size());
        }
        List<String> tags = rs.getTags();
        if (tags != null && !tags.isEmpty()) {
            return Constant.messages.getString(
                    "commonlib.gspm.dialog.rulesets.match.tags", String.join(", ", tags));
        }
        String category = rs.getCategory();
        if (category == null || category.equalsIgnoreCase(GspmRuleSet.ALL_CATEGORY)) {
            return Constant.messages.getString("commonlib.gspm.dialog.rulesets.match.all");
        }
        if (category.startsWith(GspmRuleSet.PHASE_PREFIX)) {
            return Constant.messages.getString(
                    "commonlib.gspm.dialog.rulesets.match.phase",
                    category.substring(GspmRuleSet.PHASE_PREFIX.length()));
        }
        return Constant.messages.getString(
                "commonlib.gspm.dialog.rulesets.match.category", category);
    }
}
