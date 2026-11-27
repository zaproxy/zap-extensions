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
package org.zaproxy.addon.commonlib.gspm;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import lombok.Getter;
import lombok.Setter;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;

/**
 * A set of rules within a {@link GspmPolicy} that share a common threshold and/or strength
 * override.
 *
 * <p>A rule set can combine any of {@link #category}, {@link #status}, and {@link #tags} — when
 * more than one is set, a rule must satisfy <em>all</em> of them (tags themselves use OR semantics:
 * a rule matches if it has any of the specified tags). Leaving all three unset (and no explicit
 * {@link #rules}) makes it a <em>catch-all</em> that applies to every rule in the policy.
 *
 * <p>The one exception is {@link #rules}: when a rule set has an explicit rules list, matching is
 * decided purely by whether the candidate rule's id is in that list — {@link #category}, {@link
 * #status}, and {@link #tags} are not consulted at all for that rule set.
 *
 * @since 1.45.0
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@Getter
@Setter
public class GspmRuleSet {

    /**
     * The category key representing "all rules" (the catch-all root), e.g. as a rule set's {@link
     * #category}.
     */
    public static final String ALL_CATEGORY = "all";

    /**
     * Prefix of every other category key: each {@link #ruleCategoryKey(GspmRule) rule's category
     * key} starts with its {@link #phaseKey(GspmPhase) phase key}, e.g. {@code "phase.passive"}
     * matches every rule whose {@link GspmRule#getPhase()} is {@link GspmPhase#PASSIVE}, regardless
     * of tool; see {@link #matches(GspmRule)}.
     */
    public static final String PHASE_PREFIX = "phase.";

    /**
     * Returns the category key for {@code phase}, e.g. {@code "phase.passive"}, lowercase to match
     * the convention used by every other category key (see {@link #ruleCategoryKey(GspmRule)}).
     */
    public static String phaseKey(GspmPhase phase) {
        return PHASE_PREFIX + phase.name().toLowerCase(Locale.ROOT);
    }

    /**
     * Tells whether or not {@code categoryKey} is the key of a whole phase (e.g. {@code
     * "phase.passive"}), as opposed to one of a category within a phase (e.g. {@code
     * "phase.passive.websocket"}) or not phase-scoped at all.
     */
    public static boolean isPhaseOnlyKey(String categoryKey) {
        return categoryKey != null
                && categoryKey.startsWith(PHASE_PREFIX)
                && categoryKey.indexOf('.', PHASE_PREFIX.length()) < 0;
    }

    private String name;
    private String category;
    private String status;
    private List<String> tags;
    private List<GspmRuleRef> rules;
    private String threshold;
    private String strength;

    /** Returns the threshold as an enum. Returns {@link AlertThreshold#MEDIUM} if not set. */
    @JsonIgnore
    public AlertThreshold getThresholdEnum() {
        if (threshold == null) {
            return AlertThreshold.MEDIUM;
        }
        return AlertThreshold.valueOf(threshold.toUpperCase(Locale.ROOT));
    }

    /** Sets the threshold from an enum value. */
    @JsonIgnore
    public void setThresholdEnum(AlertThreshold t) {
        this.threshold = t == null ? null : t.name();
    }

    /** Returns the strength as an enum. Returns {@link AttackStrength#MEDIUM} if not set. */
    @JsonIgnore
    public AttackStrength getStrengthEnum() {
        if (strength == null) {
            return AttackStrength.MEDIUM;
        }
        return AttackStrength.valueOf(strength.toUpperCase(Locale.ROOT));
    }

    /** Sets the strength from an enum value. */
    @JsonIgnore
    public void setStrengthEnum(AttackStrength s) {
        this.strength = s == null ? null : s.name();
    }

    /**
     * Returns {@code true} if this rule set is a catch-all: no explicit rules, no tags, no category
     * filter (or category is "all"), and no status filter.
     */
    boolean isCatchAll() {
        if (rules != null && !rules.isEmpty()) {
            return false;
        }
        if (tags != null && !tags.isEmpty()) {
            return false;
        }
        if (category != null && !category.equalsIgnoreCase(ALL_CATEGORY)) {
            return false;
        }
        if (status != null) {
            return false;
        }
        return true;
    }

    /**
     * Returns {@code true} if this rule set is a dedicated single-rule override for the given id:
     * exactly one rule entry with that id and no tags, category, or status.
     */
    boolean isPerRule(int ruleId) {
        if (rules == null || rules.size() != 1) {
            return false;
        }
        if (rules.get(0).getId() != ruleId) {
            return false;
        }
        if (tags != null && !tags.isEmpty()) {
            return false;
        }
        if (category != null) {
            return false;
        }
        if (status != null) {
            return false;
        }
        return true;
    }

    /**
     * Returns {@code true} if this rule set has no {@link #name} of its own and its shape doesn't
     * already have an unambiguous synthesized display: a true {@link #isCatchAll() catch-all}, a
     * plain phase or category scope (a non-null, non-{@link #ALL_CATEGORY} {@link #category}), or a
     * single explicit rule override ({@link #rules} of size 1, which is shown unambiguously as
     * "Rule override: X" regardless of anything else — see {@code
     * GspmRuleSetTableModel#displayName}, which this must stay in sync with).
     *
     * <p>What's left, and thus flagged here, is: a tag- and/or status-scoped rule set with no
     * category, or a multi-rule override group with no category — both of which the display
     * fallback would otherwise show as a plain, misleading "Catch-all". Used to decide which rule
     * sets get a {@link GspmPolicy#nextDefaultRuleSetName() generated default name} after
     * loading/importing a policy.
     */
    boolean needsDefaultName() {
        if (name != null && !name.isBlank()) {
            return false;
        }
        if (rules != null && rules.size() == 1) {
            return false;
        }
        boolean categoryIsAllOrUnset = category == null || category.equalsIgnoreCase(ALL_CATEGORY);
        return categoryIsAllOrUnset && !isCatchAll();
    }

    /** Lazily initialises the rules list and appends the given ref. */
    public void addRule(GspmRuleRef ref) {
        if (rules == null) {
            rules = new ArrayList<>();
        }
        rules.add(ref);
    }

    /**
     * Returns {@code true} if this rule set applies to the given rule.
     *
     * <p>If an explicit rules list is present, match is decided solely by whether the rule's id is
     * in that list — {@link #category}, {@link #status}, and {@link #tags} are ignored entirely.
     *
     * <p>Otherwise, all of the following that are set must be satisfied (unset ones are treated as
     * satisfied, so a rule set with none of them set is a catch-all that matches everything):
     *
     * <ul>
     *   <li>{@link #tags} — the rule's alert tags contain any of the specified tags (OR semantics).
     *   <li>{@link #category} (when not {@code "all"}) — equals or is a parent of the rule's
     *       category key.
     *   <li>{@link #status} — equals the rule's maturity status.
     * </ul>
     */
    public boolean matches(GspmRule rule) {
        if (rules != null && !rules.isEmpty()) {
            int id = rule.getId();
            for (GspmRuleRef ref : rules) {
                if (ref.getId() == id) {
                    return true;
                }
            }
            return false;
        }
        boolean tagsMatch = true;
        if (tags != null && !tags.isEmpty()) {
            java.util.Map<String, String> alertTags = rule.getAlertTags();
            tagsMatch = false;
            if (alertTags != null) {
                for (String tag : tags) {
                    if (alertTags.containsKey(tag)) {
                        tagsMatch = true;
                        break;
                    }
                }
            }
        }
        boolean categoryMatches = true;
        if (category != null && !category.equalsIgnoreCase(ALL_CATEGORY)) {
            categoryMatches = matchesCategory(rule);
        }
        boolean statusMatches = status == null || status.equalsIgnoreCase(rule.getStatus().name());
        return tagsMatch && categoryMatches && statusMatches;
    }

    /**
     * Returns {@code true} if this rule set's {@link #category} is the {@link
     * #ruleCategoryKey(GspmRule) category key} of {@code rule} or one of its ancestors, e.g. {@code
     * "phase.active"} or {@code "phase.active.browser"} for a rule with the key {@code
     * "phase.active.browser.dast"}. Compared ignoring case. {@link #category} is a plain string
     * deserialized from user-editable policy YAML, so an unrecognized key (e.g. from a hand-edited
     * or version-skewed file) just doesn't match any rule.
     */
    private boolean matchesCategory(GspmRule rule) {
        String ruleKey = ruleCategoryKey(rule);
        int len = category.length();
        return ruleKey.regionMatches(true, 0, category, 0, len)
                && (ruleKey.length() == len || ruleKey.charAt(len) == '.');
    }

    /**
     * Returns a stable, non-i18n category key for the given rule, e.g. {@code
     * "phase.active.browser"}: its {@link #phaseKey(GspmPhase) phase key} followed by its category
     * ids. Rules of different tools that share a phase and category ids share the key.
     */
    public static String ruleCategoryKey(GspmRule rule) {
        StringBuilder sb = new StringBuilder(phaseKey(rule.getPhase()));
        for (GspmCategory cat : rule.getCategories()) {
            sb.append('.').append(cat.id());
        }
        return sb.toString();
    }
}
