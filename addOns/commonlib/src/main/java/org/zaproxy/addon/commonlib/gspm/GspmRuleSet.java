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
 * <p>A rule set may be:
 *
 * <ul>
 *   <li>A <em>catch-all</em> (no tags, no category, no status, no explicit rules) — applies to
 *       every rule in the policy.
 *   <li>A <em>tag-scoped</em> set — applies to rules whose alert tags contain any of the specified
 *       tags (OR semantics).
 *   <li>A <em>per-rule</em> set — explicitly lists one or more rule ids.
 * </ul>
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
     * <p>Resolution order:
     *
     * <ol>
     *   <li>If an explicit rules list is present, match if the rule's id is in the list.
     *   <li>Else if a tags list is present, match if the rule's alert tags contain any of them.
     *   <li>Otherwise, match if {@link #category} (when set, and not {@code "all"}) equals or is a
     *       parent of the rule's category key, <em>and</em> {@link #status} (when set) equals the
     *       rule's maturity status. Either or both may be unset, in which case that condition is
     *       treated as satisfied; if both are unset this is the catch-all case and always matches.
     * </ol>
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
        if (tags != null && !tags.isEmpty()) {
            java.util.Map<String, String> alertTags = rule.getAlertTags();
            if (alertTags == null) {
                return false;
            }
            for (String tag : tags) {
                if (alertTags.containsKey(tag)) {
                    return true;
                }
            }
            return false;
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
        return categoryMatches && statusMatches;
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
