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
import java.util.Collections;
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
     * Appends a new rule set to the end of the list, giving it the highest precedence under
     * last-match-wins semantics — the same position new per-rule overrides are given by {@link
     * #resolveRuleSetForOverride}.
     */
    public void addRuleSet(GspmRuleSet rs) {
        ruleSets.add(rs);
    }

    /**
     * Removes a rule set from the list.
     *
     * @return {@code true} if the rule set was present and removed
     */
    public boolean removeRuleSet(GspmRuleSet rs) {
        return ruleSets.remove(rs);
    }

    /**
     * Swaps {@code rs} with its neighbour {@code delta} positions away (e.g. {@code -1} to move it
     * up, {@code 1} to move it down), changing its precedence under last-match-wins semantics.
     * No-op if {@code rs} isn't in the list, or the target position is out of range.
     */
    public void moveRuleSet(GspmRuleSet rs, int delta) {
        int index = ruleSets.indexOf(rs);
        int target = index + delta;
        if (index < 0 || target < 0 || target >= ruleSets.size()) {
            return;
        }
        Collections.swap(ruleSets, index, target);
    }

    /**
     * Returns the next auto-incrementing default name for a new rule set in this policy, e.g.
     * {@code "Rule Set 1"}, then {@code "Rule Set 2"}, and so on — one higher than the highest
     * number already used by an existing rule set matching the same {@code
     * commonlib.gspm.ruleset.name.default} pattern. Used both to name rule sets that come from an
     * import with no name of their own, and to pre-fill the name field when adding a new rule set
     * interactively.
     */
    public String nextDefaultRuleSetName() {
        int max = 0;
        for (GspmRuleSet rs : ruleSets) {
            Integer n = parseDefaultRuleSetNumber(rs.getName());
            if (n != null) {
                max = Math.max(max, n);
            }
        }
        return Constant.messages.getString("commonlib.gspm.ruleset.name.default", max + 1);
    }

    /**
     * Assigns a generated {@link #nextDefaultRuleSetName() default name} to every rule set in this
     * policy that {@link GspmRuleSet#needsDefaultName() needs one} — i.e. has no name and would
     * otherwise be shown under the misleading "Catch-all" display fallback (a tag/status-scoped
     * rule set, or a multi-rule override group, with no category). Rule sets that already display
     * fine without a name (a true catch-all, a phase/category scope, or a single-rule override) are
     * left alone.
     *
     * <p>Called after {@link #load(File) loading} or importing a policy, so hand-edited or
     * externally authored files end up with sensible names too, not just rule sets created
     * interactively (which already get one from {@link #nextDefaultRuleSetName()} via the Add Rule
     * Set dialog).
     */
    public void assignDefaultNamesToAmbiguousRuleSets() {
        for (GspmRuleSet rs : ruleSets) {
            if (rs.needsDefaultName()) {
                rs.setName(nextDefaultRuleSetName());
            }
        }
    }

    /**
     * Returns the number carried by {@code name} if it matches the {@code
     * commonlib.gspm.ruleset.name.default} pattern (i.e. the literal text before its {@code {0}}
     * placeholder, followed by an integer), or {@code null} otherwise — e.g. for a name that isn't
     * one of ours, or one a user has since appended text to (like {@code "Rule Set 5 (copy)"}).
     */
    private static Integer parseDefaultRuleSetNumber(String name) {
        if (name == null) {
            return null;
        }
        String pattern = Constant.messages.getString("commonlib.gspm.ruleset.name.default");
        int placeholder = pattern.indexOf("{0}");
        if (placeholder < 0 || !name.startsWith(pattern.substring(0, placeholder))) {
            return null;
        }
        try {
            return Integer.parseInt(name.substring(placeholder).trim());
        } catch (NumberFormatException e) {
            return null;
        }
    }

    /**
     * Returns the effective {@link AlertThreshold} for the given rule by iterating all rule sets in
     * order; the last matching rule set whose threshold string is non-null wins.
     *
     * @return the effective threshold, or empty if no rule set matches with a non-null threshold
     */
    public Optional<AlertThreshold> getEffectiveThreshold(GspmRule rule) {
        GspmRuleSet rs = getEffectiveThresholdRuleSet(rule).orElse(null);
        return rs == null ? Optional.empty() : Optional.of(rs.getThresholdEnum());
    }

    /**
     * Returns the rule set responsible for the given rule's {@link #getEffectiveThreshold(GspmRule)
     * effective threshold} — i.e. the same last-match-wins rule set {@code
     * getEffectiveThreshold(rule)} takes its value from — or empty if none matches with a non-null
     * threshold. Used to show the user which rule set is responsible for a rule's current
     * enabled/disabled state (a threshold of {@link AlertThreshold#OFF} disables it).
     */
    public Optional<GspmRuleSet> getEffectiveThresholdRuleSet(GspmRule rule) {
        GspmRuleSet result = null;
        for (GspmRuleSet rs : ruleSets) {
            if (rs.getThreshold() != null && rs.matches(rule)) {
                result = rs;
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
     * Sets the threshold for a specific rule.
     *
     * <p>If the rule already solely owns a rule set, or an override for it already resolves to the
     * same (threshold, strength) pair this would produce, that rule set is reused in place.
     * Otherwise, if another rule-only rule set already has exactly the resulting pair, this rule is
     * added to it instead of creating a duplicate — so several rules given the same override
     * collapse into one shared rule set. If the rule was sharing a rule set that needs a genuinely
     * different pair, it is detached from that rule set first (see {@link
     * #detachRuleFromAnyGroup(int)}) so the change never leaks onto the rules it was sharing with.
     * Only once none of those apply is a brand new dedicated rule set created, appended to the end
     * of the list so it overrides any catch-all or tag-scoped entries.
     *
     * <p>Passing {@code null} clears the per-rule threshold override; if the rule set then has
     * neither a threshold nor a strength override, it is removed entirely rather than left behind
     * as a dead entry.
     */
    public void setRuleThreshold(int id, String ruleName, AlertThreshold threshold) {
        String newValue = threshold == null ? null : threshold.name();
        GspmRuleSet rs = resolveRuleSetForOverride(id, ruleName, true, newValue);
        rs.setThreshold(newValue);
        removeIfEmptyPerRuleRuleSet(rs);
    }

    /**
     * Sets the strength for a specific rule. See {@link #setRuleThreshold} for how an existing rule
     * set is reused, shared, or split.
     *
     * <p>Passing {@code null} clears the per-rule strength override; if the rule set then has
     * neither a threshold nor a strength override, it is removed entirely rather than left behind
     * as a dead entry.
     */
    public void setRuleStrength(int id, String ruleName, AttackStrength strength) {
        String newValue = strength == null ? null : strength.name();
        GspmRuleSet rs = resolveRuleSetForOverride(id, ruleName, false, newValue);
        rs.setStrength(newValue);
        removeIfEmptyPerRuleRuleSet(rs);
    }

    /**
     * Removes any threshold/strength override for the given rule id, so it falls back to the
     * resolved category/catch-all default. No-op if no override exists for this rule id.
     */
    public void clearRuleOverride(int id) {
        detachRuleFromAnyGroup(id);
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
     * itself so it can later be removed via {@link #deleteFile()}. Also {@link
     * #assignDefaultNamesToAmbiguousRuleSets() assigns default names} to any loaded rule set that
     * needs one — covers hand-edited or externally authored files, not just ones round-tripped
     * through this application.
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
        policy.assignDefaultNamesToAmbiguousRuleSets();
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
     * Returns {@code true} if a rule set already exists for {@code categoryKey} (or for the
     * catch-all, when passing {@code "all"} or {@code null}).
     */
    public boolean hasCategoryRuleSet(String categoryKey) {
        return findCategoryRuleSet(categoryKey) != null;
    }

    /**
     * Returns the rule set for {@code categoryKey}, creating one if it does not exist. Rule sets
     * are kept in ascending order of category-key {@link #specificity(String)} so that more
     * specific categories appear later and win under last-match semantics. Per-rule rule sets
     * always remain at the end.
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
        int newSpecificity = specificity(categoryKey);
        for (int i = 0; i < ruleSets.size(); i++) {
            GspmRuleSet rs = ruleSets.get(i);
            if (rs.getRules() != null && !rs.getRules().isEmpty()) {
                break; // stop before per-rule ruleSets
            }
            if (specificity(rs.getCategory()) <= newSpecificity) {
                insertIdx = i + 1;
            }
        }
        ruleSets.add(insertIdx, newRs);
        return newRs;
    }

    /**
     * Returns a specificity score used to order category-scoped rule sets so more specific ones win
     * under last-match semantics: catch-all ({@code null}/{@code "all"}) is least specific, {@link
     * GspmRuleSet#PHASE_PREFIX}-scoped keys (e.g. {@code "phase.passive"}) are more specific than
     * the catch-all but less specific than any tool/category key (regardless of their own string
     * length, which has no relation to {@link GspmRuleSet#ruleCategoryKey(GspmRule)}'s tool-first
     * hierarchy), and tool/category keys fall back to string length, since {@code ruleCategoryKey}
     * nests more specific segments onto longer strings.
     */
    private static int specificity(String categoryKey) {
        if (categoryKey == null) {
            return 0;
        }
        if (categoryKey.startsWith(GspmRuleSet.PHASE_PREFIX)) {
            return 1;
        }
        return categoryKey.length() + 1;
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

    /**
     * Returns the first catch-all rule set, or {@code null} if none exists — unlike {@link
     * #findOrCreateCategoryRuleSet}/{@link #getOrCreateCatchAllRuleSet}, never creates one, so it's
     * safe to call from a read-only view (e.g. to show its {@link GspmRuleSet#getName()
     * name}/display as the fallback "responsible" rule set for a rule with no more specific
     * override).
     */
    public GspmRuleSet findCatchAllRuleSet() {
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
     * Resolves the rule set that should carry a per-rule override for {@code id} on the dimension
     * identified by {@code isThreshold} (threshold when {@code true}, strength when {@code false}),
     * given the new value for that dimension ({@code newValue}, or {@code null} to clear it):
     *
     * <ol>
     *   <li>If {@code id} already belongs to a rule set that either solely owns it, or already
     *       resolves to the same resulting (threshold, strength) pair, that rule set is reused in
     *       place — safe either way, since nothing else is affected.
     *   <li>Otherwise, if {@code id} was sharing a rule set that needs a genuinely different pair,
     *       it is detached from that rule set first (see {@link #detachRuleFromAnyGroup(int)}) so
     *       the change doesn't leak onto the other rules still referencing it.
     *   <li>If the resulting pair has at least one non-null value, an existing {@link
     *       #isRuleOnlyGroup rule-only} rule set that already has exactly that pair is reused,
     *       adding {@code id} to it — collapsing identical per-rule overrides into one shared rule
     *       set instead of each getting its own.
     *   <li>Otherwise, a brand new rule set dedicated to just {@code id} is created and appended.
     * </ol>
     */
    private GspmRuleSet resolveRuleSetForOverride(
            int id, String ruleName, boolean isThreshold, String newValue) {
        GspmRuleSet existing = null;
        for (GspmRuleSet rs : ruleSets) {
            if (hasRuleRef(rs, id)) {
                existing = rs;
                break;
            }
        }

        String finalThreshold = isThreshold ? newValue : null;
        String finalStrength = isThreshold ? null : newValue;
        if (existing != null) {
            List<GspmRuleRef> refs = existing.getRules();
            String currentThreshold = existing.getThreshold();
            String currentStrength = existing.getStrength();
            finalThreshold = isThreshold ? newValue : currentThreshold;
            finalStrength = isThreshold ? currentStrength : newValue;
            boolean soleMember = refs != null && refs.size() == 1;
            if (soleMember
                    || (Objects.equals(currentThreshold, finalThreshold)
                            && Objects.equals(currentStrength, finalStrength))) {
                return existing;
            }
            detachRuleFromAnyGroup(id);
        }

        if (finalThreshold != null || finalStrength != null) {
            for (GspmRuleSet rs : ruleSets) {
                if (isRuleOnlyGroup(rs)
                        && Objects.equals(rs.getThreshold(), finalThreshold)
                        && Objects.equals(rs.getStrength(), finalStrength)) {
                    rs.addRule(new GspmRuleRef(id, ruleName));
                    return rs;
                }
            }
        }

        GspmRuleSet newRs = new GspmRuleSet();
        newRs.addRule(new GspmRuleRef(id, ruleName));
        newRs.setThreshold(finalThreshold);
        newRs.setStrength(finalStrength);
        ruleSets.add(newRs);
        return newRs;
    }

    /** Returns {@code true} if {@code rs}'s explicit rules list references {@code id}. */
    private static boolean hasRuleRef(GspmRuleSet rs, int id) {
        List<GspmRuleRef> refs = rs.getRules();
        if (refs == null) {
            return false;
        }
        for (GspmRuleRef ref : refs) {
            if (ref.getId() == id) {
                return true;
            }
        }
        return false;
    }

    /**
     * Returns {@code true} if {@code rs} matches purely by a non-empty explicit rules list — no
     * tags, category, or status — making it safe to add another rule id to without changing what it
     * matches beyond that one extra rule.
     */
    private static boolean isRuleOnlyGroup(GspmRuleSet rs) {
        List<GspmRuleRef> refs = rs.getRules();
        return refs != null
                && !refs.isEmpty()
                && (rs.getTags() == null || rs.getTags().isEmpty())
                && rs.getCategory() == null
                && rs.getStatus() == null;
    }

    /**
     * Removes {@code id} from whatever rule set currently references it in its explicit rules list
     * (regardless of any tags/category/status also present, e.g. on a legacy-migrated rule set),
     * deleting that rule set once it no longer references any rule. No-op if not found.
     */
    private void detachRuleFromAnyGroup(int id) {
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
     * Removes {@code rs} (a per-rule rule set returned by {@link #resolveRuleSetForOverride}) if it
     * no longer has a threshold or strength override, so cleared overrides don't linger as dead
     * entries in the saved policy.
     */
    private void removeIfEmptyPerRuleRuleSet(GspmRuleSet rs) {
        if (rs.getThreshold() == null && rs.getStrength() == null) {
            ruleSets.remove(rs);
        }
    }
}
