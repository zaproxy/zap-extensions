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

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;
import net.sf.json.JSONObject;
import org.apache.commons.lang3.StringUtils;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.zaproxy.addon.commonlib.gspm.GspmPolicy;
import org.zaproxy.addon.commonlib.gspm.GspmRegistry;
import org.zaproxy.addon.commonlib.gspm.GspmRule;
import org.zaproxy.zap.extension.api.ApiAction;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.extension.api.ApiImplementor;
import org.zaproxy.zap.extension.api.ApiResponse;
import org.zaproxy.zap.extension.api.ApiResponseElement;
import org.zaproxy.zap.extension.api.ApiResponseList;
import org.zaproxy.zap.extension.api.ApiView;

/**
 * The API of the Global Scan Policy Manager.
 *
 * <p>Currently it only has the endpoints needed to redirect the policy related actions of the
 * active scan API.
 */
public class GlobalScanPolicyApi extends ApiImplementor {

    /** The prefix of the API. */
    public static final String PREFIX = "globalScanPolicy";

    private static final String VIEW_POLICY_NAMES = "policyNames";

    private static final String ACTION_ADD_POLICY = "addPolicy";
    private static final String ACTION_REMOVE_POLICY = "removePolicy";
    private static final String ACTION_UPDATE_POLICY = "updatePolicy";
    private static final String ACTION_IMPORT_LEGACY_POLICY = "importLegacyPolicy";
    private static final String ACTION_ENABLE_ALL_RULES = "enableAllRules";
    private static final String ACTION_DISABLE_ALL_RULES = "disableAllRules";
    private static final String ACTION_ENABLE_RULES = "enableRules";
    private static final String ACTION_DISABLE_RULES = "disableRules";
    private static final String ACTION_SET_ENABLED_CATEGORIES = "setEnabledCategories";
    private static final String ACTION_SET_CATEGORY_THRESHOLD = "setCategoryThreshold";
    private static final String ACTION_SET_CATEGORY_STRENGTH = "setCategoryStrength";
    private static final String ACTION_SET_RULE_THRESHOLD = "setRuleThreshold";
    private static final String ACTION_SET_RULE_STRENGTH = "setRuleStrength";

    private static final String PARAM_POLICY_NAME = "policyName";
    private static final String PARAM_TOOL = "tool";
    private static final String PARAM_PATH = "path";
    private static final String PARAM_RULE_IDS = "ruleIds";
    private static final String PARAM_RULE_ID = "ruleId";
    private static final String PARAM_CATEGORY_KEYS = "categoryKeys";
    private static final String PARAM_CATEGORY_KEY = "categoryKey";
    private static final String PARAM_ALERT_THRESHOLD = "alertThreshold";
    private static final String PARAM_ATTACK_STRENGTH = "attackStrength";

    private final GspmRegistry registry;

    /**
     * Constructs a {@code GlobalScanPolicyApi} with the given registry.
     *
     * @param registry the registry with the policies.
     */
    public GlobalScanPolicyApi(GspmRegistry registry) {
        this.registry = registry;

        addApiView(new ApiView(VIEW_POLICY_NAMES));

        String[] defaults = {PARAM_TOOL, PARAM_ALERT_THRESHOLD, PARAM_ATTACK_STRENGTH};
        addApiAction(new ApiAction(ACTION_ADD_POLICY, new String[] {PARAM_POLICY_NAME}, defaults));
        addApiAction(
                new ApiAction(ACTION_UPDATE_POLICY, new String[] {PARAM_POLICY_NAME}, defaults));
        addApiAction(new ApiAction(ACTION_REMOVE_POLICY, new String[] {PARAM_POLICY_NAME}));
        addApiAction(new ApiAction(ACTION_IMPORT_LEGACY_POLICY, new String[] {PARAM_PATH}));

        String[] policyAndTool = {PARAM_POLICY_NAME, PARAM_TOOL};
        addApiAction(new ApiAction(ACTION_ENABLE_ALL_RULES, policyAndTool));
        addApiAction(new ApiAction(ACTION_DISABLE_ALL_RULES, policyAndTool));

        String[] policyAndRules = {PARAM_POLICY_NAME, PARAM_RULE_IDS};
        String[] optionalTool = {PARAM_TOOL};
        addApiAction(new ApiAction(ACTION_ENABLE_RULES, policyAndRules, optionalTool));
        addApiAction(new ApiAction(ACTION_DISABLE_RULES, policyAndRules, optionalTool));
        addApiAction(
                new ApiAction(
                        ACTION_SET_RULE_THRESHOLD,
                        new String[] {PARAM_POLICY_NAME, PARAM_RULE_ID, PARAM_ALERT_THRESHOLD},
                        optionalTool));
        addApiAction(
                new ApiAction(
                        ACTION_SET_RULE_STRENGTH,
                        new String[] {PARAM_POLICY_NAME, PARAM_RULE_ID, PARAM_ATTACK_STRENGTH},
                        optionalTool));

        addApiAction(
                new ApiAction(
                        ACTION_SET_ENABLED_CATEGORIES,
                        new String[] {PARAM_POLICY_NAME, PARAM_TOOL, PARAM_CATEGORY_KEYS}));
        addApiAction(
                new ApiAction(
                        ACTION_SET_CATEGORY_THRESHOLD,
                        new String[] {
                            PARAM_POLICY_NAME, PARAM_TOOL, PARAM_CATEGORY_KEY, PARAM_ALERT_THRESHOLD
                        }));
        addApiAction(
                new ApiAction(
                        ACTION_SET_CATEGORY_STRENGTH,
                        new String[] {
                            PARAM_POLICY_NAME, PARAM_TOOL, PARAM_CATEGORY_KEY, PARAM_ATTACK_STRENGTH
                        }));
    }

    @Override
    public String getPrefix() {
        return PREFIX;
    }

    /**
     * The prefix of the keys of the messages, it has to be the one of the add-on for the messages
     * to be found.
     */
    @Override
    protected String getI18nPrefix() {
        return "commonlib." + PREFIX;
    }

    @Override
    public ApiResponse handleApiView(String name, JSONObject params) throws ApiException {
        if (VIEW_POLICY_NAMES.equals(name)) {
            ApiResponseList result = new ApiResponseList(name);
            for (GspmPolicy policy : registry.getAllPolicies()) {
                result.addItem(new ApiResponseElement("policy", policy.getName()));
            }
            return result;
        }
        throw new ApiException(ApiException.Type.BAD_VIEW, name);
    }

    @Override
    public ApiResponse handleApiAction(String name, JSONObject params) throws ApiException {
        try {
            switch (name) {
                case ACTION_ADD_POLICY:
                    addPolicy(params);
                    break;
                case ACTION_REMOVE_POLICY:
                    removePolicy(params);
                    break;
                case ACTION_UPDATE_POLICY:
                    updatePolicy(params);
                    break;
                case ACTION_IMPORT_LEGACY_POLICY:
                    importLegacyPolicy(params);
                    break;
                case ACTION_ENABLE_ALL_RULES:
                    GspmPolicyOperations.setAllRulesEnabled(
                            registry, getPolicyName(params), getTool(params, true), true);
                    break;
                case ACTION_DISABLE_ALL_RULES:
                    GspmPolicyOperations.setAllRulesEnabled(
                            registry, getPolicyName(params), getTool(params, true), false);
                    break;
                case ACTION_ENABLE_RULES:
                    setRulesEnabled(params, true);
                    break;
                case ACTION_DISABLE_RULES:
                    setRulesEnabled(params, false);
                    break;
                case ACTION_SET_ENABLED_CATEGORIES:
                    setEnabledCategories(params);
                    break;
                case ACTION_SET_CATEGORY_THRESHOLD:
                    String thresholdPolicy = getPolicyName(params);
                    String thresholdTool = getTool(params, true);
                    GspmPolicyOperations.setCategoryThreshold(
                            registry,
                            thresholdPolicy,
                            thresholdTool,
                            getCategoryKey(params, thresholdTool),
                            getThreshold(params, PARAM_ALERT_THRESHOLD));
                    break;
                case ACTION_SET_CATEGORY_STRENGTH:
                    String strengthPolicy = getPolicyName(params);
                    String strengthTool = getTool(params, true);
                    GspmPolicyOperations.setCategoryStrength(
                            registry,
                            strengthPolicy,
                            strengthTool,
                            getCategoryKey(params, strengthTool),
                            getStrength(params, PARAM_ATTACK_STRENGTH));
                    break;
                case ACTION_SET_RULE_THRESHOLD:
                    String ruleThresholdPolicy = getPolicyName(params);
                    String ruleThresholdTool = getTool(params, false);
                    GspmPolicyOperations.setRuleThreshold(
                            registry,
                            ruleThresholdPolicy,
                            ruleThresholdTool,
                            getRuleId(params, ruleThresholdTool),
                            getThreshold(params, PARAM_ALERT_THRESHOLD));
                    break;
                case ACTION_SET_RULE_STRENGTH:
                    String ruleStrengthPolicy = getPolicyName(params);
                    String ruleStrengthTool = getTool(params, false);
                    GspmPolicyOperations.setRuleStrength(
                            registry,
                            ruleStrengthPolicy,
                            ruleStrengthTool,
                            getRuleId(params, ruleStrengthTool),
                            getStrength(params, PARAM_ATTACK_STRENGTH));
                    break;
                default:
                    throw new ApiException(ApiException.Type.BAD_ACTION, name);
            }
        } catch (IllegalArgumentException e) {
            throw new ApiException(ApiException.Type.ILLEGAL_PARAMETER, e.getMessage(), e);
        } catch (RuntimeException e) {
            throw new ApiException(ApiException.Type.INTERNAL_ERROR, e);
        }
        return ApiResponseElement.OK;
    }

    private void addPolicy(JSONObject params) throws ApiException {
        String name = getParam(params, PARAM_POLICY_NAME, "");
        if (StringUtils.isBlank(name)) {
            throw new ApiException(ApiException.Type.MISSING_PARAMETER, PARAM_POLICY_NAME);
        }
        if (registry.getPolicy(name) != null) {
            throw new ApiException(ApiException.Type.ALREADY_EXISTS, PARAM_POLICY_NAME);
        }
        if (!GspmPolicy.isLegalPolicyName(name)) {
            throw new ApiException(ApiException.Type.ILLEGAL_PARAMETER, PARAM_POLICY_NAME);
        }
        GspmPolicyOperations.addPolicy(
                registry,
                name,
                getTool(params, false),
                getDefaultThreshold(params),
                getDefaultStrength(params));
    }

    private void removePolicy(JSONObject params) throws ApiException {
        String name = getPolicyName(params);
        if (registry.getAllPolicies().size() == 1) {
            throw new ApiException(
                    ApiException.Type.ILLEGAL_PARAMETER,
                    "You are not allowed to remove the last scan policy");
        }
        GspmPolicyOperations.removePolicy(registry, name);
    }

    private void updatePolicy(JSONObject params) throws ApiException {
        String name = getPolicyName(params);
        AlertThreshold threshold = getDefaultThreshold(params);
        AttackStrength strength = getDefaultStrength(params);
        if (threshold != null || strength != null) {
            GspmPolicyOperations.updatePolicy(
                    registry, name, getTool(params, false), threshold, strength);
        }
    }

    private void importLegacyPolicy(JSONObject params) throws ApiException {
        String path = getParam(params, PARAM_PATH, "");
        if (StringUtils.isBlank(path)) {
            throw new ApiException(ApiException.Type.MISSING_PARAMETER, PARAM_PATH);
        }
        File file = new File(path);
        if (!file.exists()) {
            throw new ApiException(ApiException.Type.DOES_NOT_EXIST, PARAM_PATH);
        }
        if (!file.isFile()) {
            throw new ApiException(ApiException.Type.ILLEGAL_PARAMETER, PARAM_PATH);
        }
        try {
            GspmPolicyOperations.importPolicy(registry, file);
        } catch (IOException e) {
            throw new ApiException(ApiException.Type.BAD_EXTERNAL_DATA, file.toString(), e);
        } catch (IllegalStateException e) {
            throw new ApiException(ApiException.Type.ALREADY_EXISTS, e.getMessage());
        } catch (IllegalArgumentException e) {
            throw new ApiException(ApiException.Type.BAD_EXTERNAL_DATA, e.getMessage());
        }
    }

    private void setRulesEnabled(JSONObject params, boolean enabled) throws ApiException {
        String policyName = getPolicyName(params);
        String tool = getTool(params, false);
        Set<Integer> knownRules =
                getRules(tool).stream().map(GspmRule::getId).collect(Collectors.toSet());
        List<Integer> ruleIds = new ArrayList<>();
        List<String> unknownIds = new ArrayList<>();
        NumberFormatException invalidId = null;
        for (String id : getParam(params, PARAM_RULE_IDS, "").split(",")) {
            String trimmed = id.trim();
            try {
                int ruleId = Integer.parseInt(trimmed);
                if (knownRules.contains(ruleId)) {
                    ruleIds.add(ruleId);
                } else {
                    unknownIds.add(trimmed);
                }
            } catch (NumberFormatException e) {
                invalidId = e;
                break;
            }
        }
        // Apply the valid ones before failing, as done by the active scan API.
        GspmPolicyOperations.setRulesEnabled(registry, policyName, tool, ruleIds, enabled);
        if (invalidId != null) {
            throw new ApiException(
                    ApiException.Type.ILLEGAL_PARAMETER, invalidId.getMessage(), invalidId);
        }
        if (!unknownIds.isEmpty()) {
            throw new ApiException(ApiException.Type.DOES_NOT_EXIST, "IDs: " + unknownIds);
        }
    }

    private void setEnabledCategories(JSONObject params) throws ApiException {
        String policyName = getPolicyName(params);
        String tool = getTool(params, true);
        List<String> categoryKeys = new ArrayList<>();
        for (String key : getParam(params, PARAM_CATEGORY_KEYS, "").split(",")) {
            categoryKeys.add(verifyCategoryKey(tool, key.trim(), PARAM_CATEGORY_KEYS));
        }
        GspmPolicyOperations.setEnabledCategories(registry, policyName, tool, categoryKeys);
    }

    private String getPolicyName(JSONObject params) throws ApiException {
        String name = getParam(params, PARAM_POLICY_NAME, "");
        if (registry.getPolicy(name) == null) {
            throw new ApiException(ApiException.Type.DOES_NOT_EXIST, PARAM_POLICY_NAME);
        }
        return name;
    }

    /**
     * Gets the tool.
     *
     * @param required {@code true} if the tool is mandatory.
     * @return the tool, {@code null} if not required and not specified.
     */
    private String getTool(JSONObject params, boolean required) throws ApiException {
        String tool = getParam(params, PARAM_TOOL, "");
        if (StringUtils.isBlank(tool)) {
            if (required) {
                throw new ApiException(ApiException.Type.MISSING_PARAMETER, PARAM_TOOL);
            }
            return null;
        }
        if (registry.getTool(tool) == null && registry.getRulesByTool(tool).isEmpty()) {
            throw new ApiException(ApiException.Type.DOES_NOT_EXIST, PARAM_TOOL);
        }
        return tool;
    }

    /** Gets the rules of the tool, or all of them if {@code null}. */
    private List<GspmRule> getRules(String tool) {
        return tool != null ? registry.getRulesByTool(tool) : registry.getAllRules();
    }

    private int getRuleId(JSONObject params, String tool) throws ApiException {
        int id = getParam(params, PARAM_RULE_ID, -1);
        if (getRules(tool).stream().noneMatch(r -> r.getId() == id)) {
            throw new ApiException(ApiException.Type.DOES_NOT_EXIST, PARAM_RULE_ID);
        }
        return id;
    }

    private String getCategoryKey(JSONObject params, String tool) throws ApiException {
        return verifyCategoryKey(
                tool, getParam(params, PARAM_CATEGORY_KEY, "").trim(), PARAM_CATEGORY_KEY);
    }

    private String verifyCategoryKey(String tool, String categoryKey, String paramName)
            throws ApiException {
        if (StringUtils.isBlank(categoryKey)) {
            throw new ApiException(ApiException.Type.ILLEGAL_PARAMETER, paramName);
        }
        String key = GspmPolicyOperations.categoryKey(tool, categoryKey);
        boolean exists =
                registry.getRulesByTool(tool).stream()
                        .anyMatch(r -> GspmPolicyOperations.isInCategory(r, key));
        if (!exists) {
            throw new ApiException(ApiException.Type.DOES_NOT_EXIST, categoryKey);
        }
        return categoryKey;
    }

    private static AlertThreshold getThreshold(JSONObject params, String name) throws ApiException {
        try {
            return AlertThreshold.valueOf(params.getString(name).trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            throw new ApiException(ApiException.Type.DOES_NOT_EXIST, name);
        }
    }

    private static AttackStrength getStrength(JSONObject params, String name) throws ApiException {
        try {
            return AttackStrength.valueOf(params.getString(name).trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            throw new ApiException(ApiException.Type.DOES_NOT_EXIST, name);
        }
    }

    private static AlertThreshold getDefaultThreshold(JSONObject params) throws ApiException {
        if (!isParamSet(params, PARAM_ALERT_THRESHOLD)) {
            return null;
        }
        AlertThreshold threshold = getThreshold(params, PARAM_ALERT_THRESHOLD);
        if (threshold == AlertThreshold.DEFAULT) {
            throw new ApiException(
                    ApiException.Type.ILLEGAL_PARAMETER,
                    "Default threshold must be one of OFF, LOW, MEDIUM, or HIGH.");
        }
        return threshold;
    }

    private static AttackStrength getDefaultStrength(JSONObject params) throws ApiException {
        if (!isParamSet(params, PARAM_ATTACK_STRENGTH)) {
            return null;
        }
        AttackStrength strength = getStrength(params, PARAM_ATTACK_STRENGTH);
        if (strength == AttackStrength.DEFAULT) {
            throw new ApiException(
                    ApiException.Type.ILLEGAL_PARAMETER,
                    "Default strength must be one of LOW, MEDIUM, HIGH, or INSANE.");
        }
        return strength;
    }

    private static boolean isParamSet(JSONObject params, String name) {
        return params.has(name) && StringUtils.isNotBlank(params.getString(name));
    }
}
