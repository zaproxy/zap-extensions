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

import java.awt.Window;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.zaproxy.addon.commonlib.gspm.GspmPolicy;
import org.zaproxy.addon.commonlib.gspm.GspmRule;
import org.zaproxy.addon.commonlib.gspm.GspmRuleRef;
import org.zaproxy.addon.commonlib.gspm.GspmRuleSet;
import org.zaproxy.zap.control.AddOn;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.utils.ZapHtmlLabel;
import org.zaproxy.zap.view.StandardFieldsDialog;

/**
 * Add/Edit dialog for a single {@link GspmRuleSet} within a policy, opened from the GSPM dialog's
 * "Rule Sets" panel ({@link GspmRuleSetsPanel}).
 *
 * <p>Two tabs: "General" holds {@link GspmRuleSet#getCategory() category}, {@link
 * GspmRuleSet#getTags() tags}, {@link GspmRuleSet#getStatus() status}, threshold, and strength, all
 * independently editable — see {@link GspmRuleSet#matches(GspmRule)} for how they combine. "Rules"
 * holds a {@link GspmRuleShuttlePanel} for managing the rule set's explicit {@link
 * GspmRuleSet#getRules() rules} list, which (per {@code matches()}) takes precedence over the
 * General tab's criteria whenever it's non-empty.
 *
 * @since 1.45.0
 */
@SuppressWarnings("serial")
public class GspmRuleSetDialog extends StandardFieldsDialog {

    private static final long serialVersionUID = 1L;

    private static final int TAB_GENERAL = 0;
    private static final int TAB_RULES = 1;

    private static final String NAME_PARAM = "commonlib.gspm.ruleset.dialog.field.name";
    private static final String CATEGORY_PARAM = "commonlib.gspm.ruleset.dialog.field.category";
    private static final String TAGS_PARAM = "commonlib.gspm.ruleset.dialog.field.tags";
    private static final String STATUS_PARAM = "commonlib.gspm.ruleset.dialog.field.status";
    private static final String THRESHOLD_PARAM = "commonlib.gspm.ruleset.dialog.field.threshold";
    private static final String STRENGTH_PARAM = "commonlib.gspm.ruleset.dialog.field.strength";

    /** Empty label, used only where a field needs the weighty-capable overload. */
    private static final String BLANK_PARAM = "commonlib.gspm.ruleset.dialog.field.blank";

    /** The only statuses selectable in the {@code STATUS_PARAM} pulldown. */
    private static final List<AddOn.Status> SELECTABLE_STATUSES =
            List.of(AddOn.Status.alpha, AddOn.Status.beta, AddOn.Status.release);

    private final GspmPolicy policy;
    private final GspmRuleSet ruleSet;
    private final Map<String, String> labelToCategory = new LinkedHashMap<>();
    private final Map<String, AddOn.Status> labelToStatus = new LinkedHashMap<>();
    private GspmTagChooserPanel tagChooser;
    private GspmRuleShuttlePanel ruleShuttle;

    /** Creates a dialog to add a new rule set to {@code policy}. */
    public GspmRuleSetDialog(
            Window owner,
            GspmPolicy policy,
            List<GspmRule> availableRules,
            List<String> availableTags,
            Map<String, String> categoryOptions) {
        this(owner, policy, null, availableRules, availableTags, categoryOptions);
    }

    /** Creates a dialog to edit {@code ruleSet}, an existing entry in {@code policy}. */
    public GspmRuleSetDialog(
            Window owner,
            GspmPolicy policy,
            GspmRuleSet ruleSet,
            List<GspmRule> availableRules,
            List<String> availableTags,
            Map<String, String> categoryOptions) {
        super(
                owner,
                ruleSet == null
                        ? "commonlib.gspm.ruleset.dialog.title.add"
                        : "commonlib.gspm.ruleset.dialog.title.edit",
                DisplayUtils.getScaledDimension(560, 520),
                new String[] {
                    "commonlib.gspm.ruleset.dialog.tab.general",
                    "commonlib.gspm.ruleset.dialog.tab.rules"
                },
                true);
        this.policy = policy;
        this.ruleSet = ruleSet;

        // A new rule set is pre-filled with the next auto-incrementing default name (e.g. "Rule
        // Set 3") so it never needs a rename just to get past validation; an existing rule set
        // keeps showing whatever name it actually has (including none, for an implicit
        // catch-all/phase/category entry — renaming that here is a deliberate user action, not
        // something to pre-fill for them).
        addTextField(
                TAB_GENERAL,
                NAME_PARAM,
                ruleSet != null
                        ? (ruleSet.getName() != null ? ruleSet.getName() : "")
                        : policy.nextDefaultRuleSetName());

        labelToCategory.putAll(invert(categoryOptions));
        List<String> categoryLabels = new ArrayList<>(categoryOptions.values());
        String currentCategory =
                ruleSet != null && ruleSet.getCategory() != null
                        ? ruleSet.getCategory()
                        : GspmRuleSet.ALL_CATEGORY;
        String initialCategory = categoryOptions.get(currentCategory);
        addComboField(
                TAB_GENERAL,
                CATEGORY_PARAM,
                categoryLabels,
                initialCategory != null ? initialCategory : categoryLabels.get(0));

        tagChooser =
                new GspmTagChooserPanel(
                        availableTags,
                        ruleSet != null && ruleSet.getTags() != null
                                ? ruleSet.getTags()
                                : List.of());
        addCustomComponent(TAB_GENERAL, TAGS_PARAM, tagChooser);

        String anyStatusLabel =
                Constant.messages.getString("commonlib.gspm.ruleset.dialog.status.any");
        List<String> statusLabels = new ArrayList<>();
        statusLabels.add(anyStatusLabel);
        for (AddOn.Status s : SELECTABLE_STATUSES) {
            String label = GspmRuleTableModel.statusLabel(s);
            statusLabels.add(label);
            labelToStatus.put(label, s);
        }
        String initialStatus =
                ruleSet != null && ruleSet.getStatus() != null
                        ? GspmRuleTableModel.statusLabel(
                                AddOn.Status.valueOf(ruleSet.getStatus().toLowerCase(Locale.ROOT)))
                        : anyStatusLabel;
        addComboField(TAB_GENERAL, STATUS_PARAM, statusLabels, initialStatus);

        List<String> thresholdLabels = new ArrayList<>();
        for (AlertThreshold t : AlertThreshold.values()) {
            if (t != AlertThreshold.DEFAULT) {
                thresholdLabels.add(levelLabel(t.name()));
            }
        }
        AlertThreshold currentThreshold =
                ruleSet != null ? ruleSet.getThresholdEnum() : AlertThreshold.MEDIUM;
        addComboField(
                TAB_GENERAL, THRESHOLD_PARAM, thresholdLabels, levelLabel(currentThreshold.name()));

        List<String> strengthLabels = new ArrayList<>();
        for (AttackStrength s : AttackStrength.values()) {
            if (s != AttackStrength.DEFAULT) {
                strengthLabels.add(levelLabel(s.name()));
            }
        }
        AttackStrength currentStrength =
                ruleSet != null ? ruleSet.getStrengthEnum() : AttackStrength.MEDIUM;
        addComboField(
                TAB_GENERAL, STRENGTH_PARAM, strengthLabels, levelLabel(currentStrength.name()));

        // Plain JLabels have HTML rendering disabled globally (see ZapLookAndFeel); ZapHtmlLabel
        // opts back in, which is what makes the text below wrap instead of running off the dialog.
        ZapHtmlLabel rulesNote =
                new ZapHtmlLabel(
                        "<html>"
                                + Constant.messages.getString(
                                        "commonlib.gspm.ruleset.dialog.rules.note")
                                + "</html>");
        addCustomComponent(TAB_RULES, rulesNote);
        ruleShuttle =
                new GspmRuleShuttlePanel(
                        availableRules,
                        ruleSet != null && ruleSet.getRules() != null
                                ? ruleSet.getRules()
                                : List.of());
        // BLANK_PARAM only exists because this overload requires a label param; it's the only one
        // that accepts a weighty, needed so the shuttle grows to fill the tab's spare space instead
        // of being squashed to its preferred size.
        addCustomComponent(TAB_RULES, BLANK_PARAM, ruleShuttle, 1.0D);
    }

    @Override
    public String validateFields() {
        String name = getStringValue(NAME_PARAM);
        if (name == null || name.trim().isEmpty()) {
            return Constant.messages.getString("commonlib.gspm.ruleset.dialog.error.name.blank");
        }
        return null;
    }

    @Override
    public void save() {
        String categoryKey = labelToCategory.get(getStringValue(CATEGORY_PARAM));
        List<String> tags = tagChooser.getSelectedTags();
        AddOn.Status status = labelToStatus.get(getStringValue(STATUS_PARAM));
        List<GspmRuleRef> rules = ruleShuttle.getSelectedRuleRefs();

        GspmRuleSet target;
        if (rules.isEmpty() && tags.isEmpty() && status == null) {
            // Category-only, no tags/status/rules: resolve the one canonical rule set for that
            // scope (the same one the tree nodes' own threshold/strength combos use) rather than
            // creating a rule set that would silently duplicate/shadow it.
            target = policy.findOrCreateCategoryRuleSet(categoryKey);
            if (ruleSet != null && ruleSet != target) {
                policy.removeRuleSet(ruleSet);
            }
        } else {
            target = ruleSet != null ? ruleSet : new GspmRuleSet();
            target.setCategory(GspmRuleSet.ALL_CATEGORY.equals(categoryKey) ? null : categoryKey);
            target.setTags(tags.isEmpty() ? null : tags);
            target.setStatus(status == null ? null : status.name());
            target.setRules(rules.isEmpty() ? null : rules);
            if (ruleSet == null) {
                policy.addRuleSet(target);
            }
        }

        target.setName(getStringValue(NAME_PARAM).trim());
        target.setThresholdEnum(labelToThreshold(getStringValue(THRESHOLD_PARAM)));
        target.setStrengthEnum(labelToStrength(getStringValue(STRENGTH_PARAM)));
    }

    private static Map<String, String> invert(Map<String, String> keyToLabel) {
        Map<String, String> labelToKey = new LinkedHashMap<>();
        for (Map.Entry<String, String> entry : keyToLabel.entrySet()) {
            labelToKey.put(entry.getValue(), entry.getKey());
        }
        return labelToKey;
    }

    private static String levelLabel(String enumName) {
        return Constant.messages.getString(
                "ascan.policy.level." + enumName.toLowerCase(Locale.ROOT));
    }

    private static AlertThreshold labelToThreshold(String label) {
        for (AlertThreshold t : AlertThreshold.values()) {
            if (levelLabel(t.name()).equals(label)) {
                return t;
            }
        }
        return AlertThreshold.MEDIUM;
    }

    private static AttackStrength labelToStrength(String label) {
        for (AttackStrength s : AttackStrength.values()) {
            if (levelLabel(s.name()).equals(label)) {
                return s;
            }
        }
        return AttackStrength.MEDIUM;
    }
}
