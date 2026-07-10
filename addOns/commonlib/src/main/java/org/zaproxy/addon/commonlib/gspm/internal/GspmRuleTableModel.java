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
import org.zaproxy.addon.commonlib.gspm.GspmRule;
import org.zaproxy.zap.control.AddOn;

/**
 * Table model for the GSPM dialog showing one row per {@link GspmRule}.
 *
 * <p>Columns: Name, Threshold, Strength (dash for passive rules that lack attack strength), Status.
 * Threshold and Strength cells are editable for rules that support them.
 *
 * @since 1.39.0
 */
@SuppressWarnings("serial")
public class GspmRuleTableModel extends AbstractTableModel {

    private static final long serialVersionUID = 1L;

    static final int COL_NAME = 0;
    static final int COL_THRESHOLD = 1;
    static final int COL_STRENGTH = 2;
    static final int COL_STATUS = 3;
    static final int COL_COUNT = 4;

    private List<GspmRule> rules = new ArrayList<>();
    private Map<String, String> i18nToEnum;

    /** Replaces the displayed rules and fires a full table-data-changed event. */
    public void setRules(List<GspmRule> newRules) {
        this.rules = new ArrayList<>(newRules);
        i18nToEnum = null;
        fireTableDataChanged();
    }

    List<GspmRule> getRules() {
        return rules;
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
            case COL_STATUS ->
                    Constant.messages.getString("commonlib.gspm.dialog.table.col.status");
            default -> "";
        };
    }

    @Override
    public Class<?> getColumnClass(int col) {
        return String.class;
    }

    @Override
    public boolean isCellEditable(int row, int col) {
        if (col == COL_STRENGTH) {
            return rules.get(row).getAttackStrength() != null;
        }
        return col == COL_THRESHOLD;
    }

    @Override
    public Object getValueAt(int row, int col) {
        GspmRule rule = rules.get(row);
        return switch (col) {
            case COL_NAME -> rule.getName();
            case COL_THRESHOLD -> thresholdToI18n(rule.getAlertThreshold());
            case COL_STRENGTH -> {
                AttackStrength s = rule.getAttackStrength();
                yield s != null
                        ? strengthToI18n(s)
                        : Constant.messages.getString("commonlib.gspm.rule.strength.na");
            }
            case COL_STATUS -> statusLabel(rule.getStatus());
            default -> "";
        };
    }

    @Override
    public void setValueAt(Object value, int row, int col) {
        GspmRule rule = rules.get(row);
        switch (col) {
            case COL_THRESHOLD -> {
                AlertThreshold t = i18nToThreshold((String) value);
                if (t != null) {
                    rule.setEnabled(!AlertThreshold.OFF.equals(t));
                    rule.setAlertThreshold(t);
                    fireTableCellUpdated(row, col);
                }
            }
            case COL_STRENGTH -> {
                AttackStrength s = i18nToStrength((String) value);
                if (s != null) {
                    rule.setAttackStrength(s);
                    fireTableCellUpdated(row, col);
                }
            }
            default -> {
                // Name and Status columns are not editable
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

    static String statusLabel(AddOn.Status status) {
        String key = "commonlib.gspm.status." + status.name().toLowerCase(Locale.ROOT);
        return Constant.messages.containsKey(key)
                ? Constant.messages.getString(key)
                : capitalize(status.name());
    }

    private static String capitalize(String s) {
        if (s == null || s.isEmpty()) return s;
        return Character.toUpperCase(s.charAt(0)) + s.substring(1).toLowerCase(Locale.ROOT);
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
}
