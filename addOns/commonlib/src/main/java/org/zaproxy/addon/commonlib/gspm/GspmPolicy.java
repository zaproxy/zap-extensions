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
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import lombok.Getter;
import lombok.Setter;
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
 * @since 1.45.0
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class GspmPolicy {

    /** File extension used for persisted policy files. */
    public static final String EXTENSION = ".policy2";

    /** Characters not allowed in a policy name. */
    public static final String ILLEGAL_POLICY_NAME_CHRS = "/`?*\\<>|\":\t\n\r";

    public static final YAMLMapper YAML_MAPPER;

    static {
        YAML_MAPPER = YAMLMapper.builder().build();
        YAML_MAPPER.findAndRegisterModules();
    }

    @Getter private String name;
    @Getter private List<GspmRuleSet> ruleSets = new ArrayList<>();

    /**
     * Base name of the persisted file (without {@link #EXTENSION}), which may differ from {@link
     * #name} when the display name contains characters that are unsafe in file paths (e.g. {@code
     * /}). Not written to YAML; set from the source file on load or migration.
     */
    @JsonIgnore @Setter private String fileName;

    /** The file this policy was loaded from, or last saved to. */
    @JsonIgnore @Getter private File file;

    /**
     * Creates a new policy with the given name.
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

    /**
     * Renames this policy, without changing the file it is persisted to.
     *
     * <p>Callers that need to keep a {@code GspmRegistry} in sync (which indexes policies by name)
     * should use {@code GspmRegistry#renamePolicy(String, String)} instead of calling this
     * directly.
     *
     * @throws NullPointerException if {@code name} is {@code null}
     * @throws IllegalArgumentException if {@code name} is blank
     */
    public void setName(String name) {
        Objects.requireNonNull(name, "name must not be null");
        if (name.isBlank()) {
            throw new IllegalArgumentException("Policy name must not be blank");
        }
        this.name = name;
    }

    /**
     * Returns {@code true} if {@code name} does not contain any of {@link
     * #ILLEGAL_POLICY_NAME_CHRS}. Used to validate names entered interactively, e.g. in {@code
     * GspmPolicyManagerDialog}; not enforced by this constructor since a policy's display {@link
     * #getName() name} may legitimately contain such characters (e.g. {@code /}), with {@link
     * #getFileName() fileName} holding the sanitized on-disk name.
     */
    public static boolean isLegalPolicyName(String name) {
        for (int i = 0; i < name.length(); i++) {
            if (ILLEGAL_POLICY_NAME_CHRS.indexOf(name.charAt(i)) >= 0) {
                return false;
            }
        }
        return true;
    }

    /**
     * Returns the base file name used when persisting this policy (without extension). Defaults to
     * {@link #getName()} when no explicit file name has been set.
     */
    public String getFileName() {
        return fileName != null ? fileName : name;
    }

    /** Replaces the rule sets list. */
    public void setRuleSets(List<GspmRuleSet> ruleSets) {
        this.ruleSets = ruleSets != null ? ruleSets : new ArrayList<>();
    }

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

    /**
     * Sets the threshold for a specific rule, creating a dedicated single-rule rule set if one does
     * not already exist. The per-rule rule set is always appended to the end of the list so it
     * overrides any catch-all or tag-scoped entries.
     *
     * <p>Passing {@code null} clears the per-rule threshold override; if the rule set then has
     * neither a threshold nor a strength override, it is removed entirely rather than left behind
     * as a dead entry.
     */
    public void setRuleThreshold(int id, String ruleName, AlertThreshold threshold) {
        GspmRuleSet rs = findOrCreatePerRuleRuleSet(id, ruleName);
        rs.setThresholdEnum(threshold);
        removeIfEmptyPerRuleRuleSet(rs);
    }

    /**
     * Sets the strength for a specific rule, creating a dedicated single-rule rule set if one does
     * not already exist.
     *
     * <p>Passing {@code null} clears the per-rule strength override; if the rule set then has
     * neither a threshold nor a strength override, it is removed entirely rather than left behind
     * as a dead entry.
     */
    public void setRuleStrength(int id, String ruleName, AttackStrength strength) {
        GspmRuleSet rs = findOrCreatePerRuleRuleSet(id, ruleName);
        rs.setStrengthEnum(strength);
        removeIfEmptyPerRuleRuleSet(rs);
    }

    /**
     * Removes any threshold/strength override for the given rule id, so it falls back to the
     * resolved category/catch-all default.
     *
     * <p>Unlike {@link #setRuleThreshold} / {@link #setRuleStrength} (which only ever look at a
     * dedicated single-rule rule set), this also detects and cleans up rule sets shared by several
     * rules with the same value, as created by legacy policy migration: the rule id is removed from
     * any rule set that explicitly lists it, and the rule set itself is removed once it no longer
     * references any rule, without affecting other rules that still share it. No-op if no override
     * exists for this rule id.
     */
    public void clearRuleOverride(int id) {
        Iterator<GspmRuleSet> it = ruleSets.iterator();
        while (it.hasNext()) {
            GspmRuleSet rs = it.next();
            List<GspmRuleRef> refs = rs.getRules();
            if (refs == null || refs.isEmpty()) {
                continue;
            }
            if (refs.removeIf(ref -> ref.getId() == id) && refs.isEmpty()) {
                it.remove();
            }
        }
    }

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

    /**
     * Saves this policy to a YAML file in {@link Constant#getPoliciesDir()}.
     *
     * @throws IOException if the file cannot be written
     */
    public void save() throws IOException {
        save(Constant.getPoliciesDir().toPath());
    }

    /**
     * Saves this policy to a YAML file in the given directory.
     *
     * <p>Uses {@link #getFileName()} for the file base name so the on-disk name can differ from the
     * display {@link #getName()}.
     *
     * @throws IOException if the file cannot be written
     */
    public void save(Path path) throws IOException {
        File target = new File(path.toString(), getFileName() + EXTENSION);
        YAML_MAPPER.writerWithDefaultPrettyPrinter().writeValue(target, this);
        this.file = target;
    }

    /**
     * Loads a policy from the given YAML file.
     *
     * <p>Records the file's base name via {@link #setFileName(String)} so later saves reuse the
     * same file rather than deriving a path from {@link #getName()}, and remembers {@code file}
     * itself so it can later be removed via {@link #deleteFile()}.
     *
     * @throws IOException if the file cannot be read or parsed
     */
    public static GspmPolicy load(File file) throws IOException {
        GspmPolicy policy = YAML_MAPPER.readValue(file, GspmPolicy.class);
        String loadedName = file.getName();
        if (loadedName.endsWith(EXTENSION)) {
            policy.setFileName(loadedName.substring(0, loadedName.length() - EXTENSION.length()));
        }
        policy.file = file;
        return policy;
    }

    /**
     * Deletes the file this policy was loaded from or last saved to.
     *
     * <p>No-op (returning {@code true}) if this policy has never been saved or loaded, or if the
     * file does not exist. {@link #getFile()} is only cleared when deletion actually succeeds, so a
     * failure (e.g. the file is locked or read-only) doesn't cause this policy to "forget" a file
     * that's still on disk.
     *
     * @return {@code true} if the file was deleted, or there was nothing to delete
     */
    public boolean deleteFile() {
        if (file == null) {
            return true;
        }
        if (!file.delete() && file.exists()) {
            return false;
        }
        file = null;
        return true;
    }

    /**
     * Returns the existing rule set whose {@code category} field matches {@code categoryKey}, or
     * {@code null} if none exists. Passing {@code "all"} (or {@code null}) returns the catch-all.
     */
    GspmRuleSet findCategoryRuleSet(String categoryKey) {
        if (categoryKey == null || GspmRuleSet.ALL_CATEGORY.equalsIgnoreCase(categoryKey)) {
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
        if (categoryKey == null || GspmRuleSet.ALL_CATEGORY.equalsIgnoreCase(categoryKey)) {
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

    /**
     * Removes {@code rs} (a per-rule rule set returned by {@link #findOrCreatePerRuleRuleSet}) if
     * it no longer has a threshold or strength override, so cleared overrides don't linger as dead
     * entries in the saved policy.
     */
    private void removeIfEmptyPerRuleRuleSet(GspmRuleSet rs) {
        if (rs.getThreshold() == null && rs.getStrength() == null) {
            ruleSets.remove(rs);
        }
    }
}
