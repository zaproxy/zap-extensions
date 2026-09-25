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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
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

    private static final Logger LOGGER = LogManager.getLogger(GspmRuleSet.class);

    /**
     * The category id/key representing "all rules" (the catch-all root), e.g. as a rule set's
     * {@link #category}, or as the root segment of a {@link #ruleCategoryKey(GspmRule) category
     * key} such as {@code "all.ascan"}.
     */
    public static final String ALL_CATEGORY = "all";

    /**
     * Prefix for a {@link #category} value that scopes a rule set to a whole {@link GspmPhase}
     * instead of a tool/category key, e.g. {@code "phase.passive"} matches every rule whose {@link
     * GspmRule#getPhase()} is {@link GspmPhase#PASSIVE}, regardless of tool. Kept as a separate
     * namespace from {@link #ruleCategoryKey(GspmRule)} (which stays tool-first, unaware of phase)
     * so existing tool/category keys are unaffected; see {@link #matches(GspmRule)}.
     */
    public static final String PHASE_PREFIX = "phase.";

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
            if (category.startsWith(PHASE_PREFIX)) {
                categoryMatches = matchesPhase(rule);
            } else {
                String ruleKey = ruleCategoryKey(rule);
                categoryMatches = ruleKey.equals(category) || ruleKey.startsWith(category + ".");
            }
        }
        boolean statusMatches = status == null || status.equalsIgnoreCase(rule.getStatus().name());
        return tagsMatch && categoryMatches && statusMatches;
    }

    /**
     * Returns {@code true} if {@code rule}'s phase matches this rule set's {@link #category}, which
     * must already be confirmed to have the {@link #PHASE_PREFIX}. {@link #category} is a plain
     * string deserialized from user-editable policy YAML, so an unrecognized phase name (e.g. from
     * a hand-edited or version-skewed file) is treated as a non-match rather than thrown, to avoid
     * breaking threshold/strength resolution for every other rule set.
     */
    private boolean matchesPhase(GspmRule rule) {
        try {
            GspmPhase phase =
                    GspmPhase.valueOf(
                            category.substring(PHASE_PREFIX.length()).toUpperCase(Locale.ROOT));
            return rule.getPhase() == phase;
        } catch (IllegalArgumentException e) {
            LOGGER.warn("GSPM: ignoring rule set with unrecognised phase category '{}'", category);
            return false;
        }
    }

    /**
     * Returns a stable, non-i18n category key for the given rule, e.g. {@code "all.ascan"} or
     * {@code "all.ascan.server-side"}. The key is built from the tool key followed by the category
     * id segments.
     */
    public static String ruleCategoryKey(GspmRule rule) {
        StringBuilder sb = new StringBuilder(ALL_CATEGORY);
        sb.append('.').append(rule.getTool());
        for (GspmCategory cat : rule.getCategories()) {
            sb.append('.').append(cat.id());
        }
        return sb.toString();
    }
}
