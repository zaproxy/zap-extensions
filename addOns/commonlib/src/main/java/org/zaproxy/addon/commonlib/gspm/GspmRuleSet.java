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
 * @since 1.39.0
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class GspmRuleSet {

    private String name;
    private String category;
    private String status;
    private List<String> tags;
    private List<GspmRuleRef> rules;
    private String threshold;
    private String strength;

    // -------------------------------------------------------------------------
    // Basic getters / setters (used by Jackson and callers)
    // -------------------------------------------------------------------------

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getCategory() {
        return category;
    }

    public void setCategory(String category) {
        this.category = category;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public List<String> getTags() {
        return tags;
    }

    public void setTags(List<String> tags) {
        this.tags = tags;
    }

    public List<GspmRuleRef> getRules() {
        return rules;
    }

    public void setRules(List<GspmRuleRef> rules) {
        this.rules = rules;
    }

    public String getThreshold() {
        return threshold;
    }

    public void setThreshold(String threshold) {
        this.threshold = threshold;
    }

    public String getStrength() {
        return strength;
    }

    public void setStrength(String strength) {
        this.strength = strength;
    }

    // -------------------------------------------------------------------------
    // Typed enum accessors (ignored by Jackson — use String fields for YAML)
    // -------------------------------------------------------------------------

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

    // -------------------------------------------------------------------------
    // Package-private helpers used by GspmPolicy
    // -------------------------------------------------------------------------

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
        if (category != null && !category.equalsIgnoreCase("all")) {
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

    // -------------------------------------------------------------------------
    // Matching
    // -------------------------------------------------------------------------

    /**
     * Returns {@code true} if this rule set applies to the given rule.
     *
     * <p>Resolution order:
     *
     * <ol>
     *   <li>If an explicit rules list is present, match if the rule's id is in the list.
     *   <li>Else if a tags list is present, match if the rule's alert tags contain any of them.
     *   <li>Else if {@link #category} is set (and not {@code "all"}), match if the rule's category
     *       key equals or is a child of this category.
     *   <li>Otherwise: catch-all, always matches.
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
        if (category != null && !category.equalsIgnoreCase("all")) {
            String ruleKey = ruleCategoryKey(rule);
            return ruleKey.equals(category) || ruleKey.startsWith(category + ".");
        }
        // catch-all
        return true;
    }

    // -------------------------------------------------------------------------
    // Helpers used by GspmPolicy and GspmDialog
    // -------------------------------------------------------------------------

    /**
     * Returns a stable, non-i18n category key for the given rule, e.g. {@code "all.ascan"} or
     * {@code "all.ascan.server-side"}. The key is built from the tool key followed by the category
     * id segments.
     */
    public static String ruleCategoryKey(GspmRule rule) {
        StringBuilder sb = new StringBuilder("all");
        sb.append('.').append(rule.getTool());
        for (GspmCategory cat : rule.getCategories()) {
            sb.append('.').append(cat.id());
        }
        return sb.toString();
    }
}
