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

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.dataformat.yaml.YAMLMapper;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;

/**
 * A named scan policy that stores a list of {@link GspmRuleSet} entries.
 *
 * <p>When the registry resolves effective configuration for a rule it iterates all rule sets in
 * order; the <em>last</em> match wins (later entries take precedence over earlier ones). This
 * allows a catch-all rule set at index 0 to provide policy-wide defaults that are overridden by
 * tag-scoped or per-rule sets that appear later in the list.
 *
 * <p>Policy files are persisted as YAML with the extension {@value #EXTENSION} in {@link
 * Constant#getPoliciesDir()}.
 *
 * @since 1.39.0
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class GspmPolicy {

    /** File extension used for persisted policy files. */
    public static final String EXTENSION = ".policy2";

    public static final YAMLMapper YAML_MAPPER;

    static {
        YAML_MAPPER = YAMLMapper.builder().build();
        YAML_MAPPER.findAndRegisterModules();
    }

    private final String name;
    private List<GspmRuleSet> ruleSets = new ArrayList<>();

    /**
     * Base name of the persisted file (without {@link #EXTENSION}), which may differ from {@link
     * #name} when the display name contains characters that are unsafe in file paths (e.g. {@code
     * /}). Not written to YAML; set from the source file on load or migration.
     */
    @JsonIgnore private String fileName;

    /**
     * Creates a new policy with the given name.
     *
     * <p>This constructor is also used by Jackson during YAML deserialization (via
     * {@code @JsonCreator}).
     *
     * @throws NullPointerException if {@code name} is {@code null}
     * @throws IllegalArgumentException if {@code name} is blank
     */
    @JsonCreator
    public GspmPolicy(@JsonProperty("name") String name) {
        this.name = Objects.requireNonNull(name, "name must not be null");
        if (name.isBlank()) {
            throw new IllegalArgumentException("Policy name must not be blank");
        }
    }

    // -------------------------------------------------------------------------
    // Core getters / setters
    // -------------------------------------------------------------------------

    /** Returns the name of this policy. */
    public String getName() {
        return name;
    }

    /**
     * Returns the base file name used when persisting this policy (without extension). Defaults to
     * {@link #getName()} when no explicit file name has been set.
     */
    public String getFileName() {
        return fileName != null ? fileName : name;
    }

    /**
     * Sets the base file name used when persisting this policy (without extension).
     *
     * @param fileName the file base name, or {@code null} to fall back to {@link #getName()}
     */
    public void setFileName(String fileName) {
        this.fileName = fileName;
    }

    /** Returns the list of rule sets in this policy (mutable). */
    public List<GspmRuleSet> getRuleSets() {
        return ruleSets;
    }

    /** Replaces the rule sets list (used by Jackson during deserialization and by tests). */
    public void setRuleSets(List<GspmRuleSet> ruleSets) {
        this.ruleSets = ruleSets != null ? ruleSets : new ArrayList<>();
    }

    // -------------------------------------------------------------------------
    // Effective value resolution
    // -------------------------------------------------------------------------

    /**
     * Returns the effective {@link AlertThreshold} for the given rule by iterating all rule sets in
     * order; the last matching rule set whose threshold string is non-null wins.
     *
     * @return the effective threshold, or empty if no rule set matches with a non-null threshold
     */
    public Optional<AlertThreshold> getEffectiveThreshold(GspmRule rule) {
        AlertThreshold result = null;
        for (GspmRuleSet rs : ruleSets) {
            if (rs.getThreshold() != null && rs.matches(rule)) {
                result = rs.getThresholdEnum();
            }
        }
        return Optional.ofNullable(result);
    }

    /**
     * Returns the effective {@link AttackStrength} for the given rule by iterating all rule sets in
     * order; the last matching rule set whose strength string is non-null wins.
     *
     * @return the effective strength, or empty if no rule set matches with a non-null strength
     */
    public Optional<AttackStrength> getEffectiveStrength(GspmRule rule) {
        AttackStrength result = null;
        for (GspmRuleSet rs : ruleSets) {
            if (rs.getStrength() != null && rs.matches(rule)) {
                result = rs.getStrengthEnum();
            }
        }
        return Optional.ofNullable(result);
    }

    // -------------------------------------------------------------------------
    // Per-rule setters
    // -------------------------------------------------------------------------

    /**
     * Sets the threshold for a specific rule, creating a dedicated single-rule rule set if one does
     * not already exist. The per-rule rule set is always appended to the end of the list so it
     * overrides any catch-all or tag-scoped entries.
     */
    public void setRuleThreshold(int id, String ruleName, AlertThreshold threshold) {
        GspmRuleSet rs = findOrCreatePerRuleRuleSet(id, ruleName);
        rs.setThresholdEnum(threshold);
    }

    /**
     * Sets the strength for a specific rule, creating a dedicated single-rule rule set if one does
     * not already exist.
     */
    public void setRuleStrength(int id, String ruleName, AttackStrength strength) {
        GspmRuleSet rs = findOrCreatePerRuleRuleSet(id, ruleName);
        rs.setStrengthEnum(strength);
    }

    // -------------------------------------------------------------------------
    // Compat API — policy-wide defaults via the catch-all rule set
    // -------------------------------------------------------------------------

    /**
     * Returns the policy-level default threshold from the first catch-all rule set, or empty if
     * none exists or the catch-all has no threshold set.
     */
    @JsonIgnore
    public Optional<AlertThreshold> getDefaultThreshold() {
        GspmRuleSet catchAll = findCatchAllRuleSet();
        if (catchAll == null || catchAll.getThreshold() == null) {
            return Optional.empty();
        }
        return Optional.of(catchAll.getThresholdEnum());
    }

    /**
     * Sets the policy-level default threshold on the catch-all rule set, creating one at index 0 if
     * needed. Passing {@code null} clears the threshold string on the catch-all.
     */
    public void setDefaultThreshold(AlertThreshold t) {
        GspmRuleSet catchAll = getOrCreateCatchAllRuleSet();
        catchAll.setThresholdEnum(t);
    }

    /**
     * Returns the policy-level default attack strength from the first catch-all rule set, or empty
     * if none exists or the catch-all has no strength set.
     */
    @JsonIgnore
    public Optional<AttackStrength> getDefaultStrength() {
        GspmRuleSet catchAll = findCatchAllRuleSet();
        if (catchAll == null || catchAll.getStrength() == null) {
            return Optional.empty();
        }
        return Optional.of(catchAll.getStrengthEnum());
    }

    /**
     * Sets the policy-level default attack strength on the catch-all rule set, creating one at
     * index 0 if needed. Passing {@code null} clears the strength string on the catch-all.
     */
    public void setDefaultStrength(AttackStrength s) {
        GspmRuleSet catchAll = getOrCreateCatchAllRuleSet();
        catchAll.setStrengthEnum(s);
    }

    // -------------------------------------------------------------------------
    // Persistence
    // -------------------------------------------------------------------------

    /**
     * Saves this policy to a YAML file in {@link Constant#getPoliciesDir()}.
     *
     * @throws IOException if the file cannot be written
     */
    public void save() throws IOException {
        save(Constant.getPoliciesDir());
    }

    /**
     * Saves this policy to a YAML file in the given directory.
     *
     * <p>Uses {@link #getFileName()} for the file base name so the on-disk name can differ from the
     * display {@link #getName()}.
     *
     * @throws IOException if the file cannot be written
     */
    public void save(File dir) throws IOException {
        YAML_MAPPER
                .writerWithDefaultPrettyPrinter()
                .writeValue(new File(dir, getFileName() + EXTENSION), this);
    }

    /**
     * Loads a policy from the given YAML file.
     *
     * <p>Records the file's base name via {@link #setFileName(String)} so later saves reuse the
     * same file rather than deriving a path from {@link #getName()}.
     *
     * @throws IOException if the file cannot be read or parsed
     */
    public static GspmPolicy load(File file) throws IOException {
        GspmPolicy policy = YAML_MAPPER.readValue(file, GspmPolicy.class);
        String loadedName = file.getName();
        if (loadedName.endsWith(EXTENSION)) {
            policy.setFileName(loadedName.substring(0, loadedName.length() - EXTENSION.length()));
        }
        return policy;
    }

    /**
     * Deletes the persisted policy file with the given base name (without extension). No-op if the
     * file does not exist.
     *
     * @param fileName the file base name as returned by {@link #getFileName()}
     */
    public static void deleteFile(String fileName) {
        new File(Constant.getPoliciesDir(), fileName + EXTENSION).delete();
    }

    // -------------------------------------------------------------------------
    // Category-scoped rule set access (used by the policy editor dialog)
    // -------------------------------------------------------------------------

    /**
     * Returns the existing rule set whose {@code category} field matches {@code categoryKey}, or
     * {@code null} if none exists. Passing {@code "all"} (or {@code null}) returns the catch-all.
     */
    GspmRuleSet findCategoryRuleSet(String categoryKey) {
        if (categoryKey == null || "all".equalsIgnoreCase(categoryKey)) {
            return findCatchAllRuleSet();
        }
        for (GspmRuleSet rs : ruleSets) {
            boolean noRules = rs.getRules() == null || rs.getRules().isEmpty();
            boolean noTags = rs.getTags() == null || rs.getTags().isEmpty();
            if (noRules
                    && noTags
                    && rs.getStatus() == null
                    && categoryKey.equals(rs.getCategory())) {
                return rs;
            }
        }
        return null;
    }

    /**
     * Returns the rule set for {@code categoryKey}, creating one if it does not exist. Rule sets
     * are kept in ascending order of category-key length so that more specific categories (longer
     * keys) appear later and win under last-match semantics. Per-rule rule sets always remain at
     * the end.
     */
    public GspmRuleSet findOrCreateCategoryRuleSet(String categoryKey) {
        if (categoryKey == null || "all".equalsIgnoreCase(categoryKey)) {
            return getOrCreateCatchAllRuleSet();
        }
        GspmRuleSet existing = findCategoryRuleSet(categoryKey);
        if (existing != null) {
            return existing;
        }
        GspmRuleSet newRs = new GspmRuleSet();
        newRs.setCategory(categoryKey);
        // Find insertion point: after all less-or-equally-specific category ruleSets but before
        // the first per-rule ruleSet.
        int insertIdx = 0;
        for (int i = 0; i < ruleSets.size(); i++) {
            GspmRuleSet rs = ruleSets.get(i);
            if (rs.getRules() != null && !rs.getRules().isEmpty()) {
                break; // stop before per-rule ruleSets
            }
            String existingCat = rs.getCategory();
            int existingLen = existingCat == null ? 0 : existingCat.length();
            if (existingLen <= categoryKey.length()) {
                insertIdx = i + 1;
            }
        }
        ruleSets.add(insertIdx, newRs);
        return newRs;
    }

    /**
     * Returns the threshold set on the rule set for {@code categoryKey}, or empty if no rule set
     * exists for that category or it has no threshold configured.
     */
    public Optional<AlertThreshold> getCategoryThreshold(String categoryKey) {
        GspmRuleSet rs = findCategoryRuleSet(categoryKey);
        if (rs == null || rs.getThreshold() == null) {
            return Optional.empty();
        }
        return Optional.of(rs.getThresholdEnum());
    }

    /**
     * Returns the strength set on the rule set for {@code categoryKey}, or empty if no rule set
     * exists for that category or it has no strength configured.
     */
    public Optional<AttackStrength> getCategoryStrength(String categoryKey) {
        GspmRuleSet rs = findCategoryRuleSet(categoryKey);
        if (rs == null || rs.getStrength() == null) {
            return Optional.empty();
        }
        return Optional.of(rs.getStrengthEnum());
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /** Returns the first catch-all rule set, or {@code null} if none exists. */
    private GspmRuleSet findCatchAllRuleSet() {
        for (GspmRuleSet rs : ruleSets) {
            if (rs.isCatchAll()) {
                return rs;
            }
        }
        return null;
    }

    /** Returns the first catch-all rule set, inserting a new empty one at index 0 if needed. */
    private GspmRuleSet getOrCreateCatchAllRuleSet() {
        GspmRuleSet existing = findCatchAllRuleSet();
        if (existing != null) {
            return existing;
        }
        GspmRuleSet newCatchAll = new GspmRuleSet();
        ruleSets.add(0, newCatchAll);
        return newCatchAll;
    }

    /**
     * Finds a dedicated single-rule rule set for the given id, or creates a new one and appends it
     * to the end of the list.
     */
    private GspmRuleSet findOrCreatePerRuleRuleSet(int id, String ruleName) {
        for (GspmRuleSet rs : ruleSets) {
            if (rs.isPerRule(id)) {
                return rs;
            }
        }
        GspmRuleSet newRs = new GspmRuleSet();
        newRs.addRule(new GspmRuleRef(id, ruleName));
        ruleSets.add(newRs);
        return newRs;
    }
}
