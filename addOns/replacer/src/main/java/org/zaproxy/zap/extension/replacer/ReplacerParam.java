/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2017 The ZAP Development Team
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
package org.zaproxy.zap.extension.replacer;

import java.util.ArrayList;
import java.util.List;
import org.apache.commons.configuration.ConversionException;
import org.apache.commons.configuration.HierarchicalConfiguration;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.addon.commonlib.http.HttpFieldsNames;
import org.zaproxy.zap.common.VersionedAbstractParam;
import org.zaproxy.zap.extension.api.ZapApiIgnore;
import org.zaproxy.zap.extension.replacer.ReplacerParamRule.MatchType;

public class ReplacerParam extends VersionedAbstractParam {

    private static final Logger LOGGER = LogManager.getLogger(ReplacerParam.class);

    private static final String REPLACER_BASE_KEY = "replacer";

    protected static final String ALL_RULES_KEY = REPLACER_BASE_KEY + ".full_list";

    protected static final String RULE_DESCRIPTION_KEY = "description";
    protected static final String RULE_URL_KEY = "url";
    protected static final String RULE_ENABLED_KEY = "enabled";
    protected static final String RULE_MATCH_STRING_KEY = "matchstr";
    protected static final String RULE_MATCH_TYPE_KEY = "matchtype";
    protected static final String RULE_REGEX_KEY = "regex";
    protected static final String RULE_REPLACEMENT_KEY = "replacement";
    protected static final String RULE_INITIATORS_KEY = "initiators";
    protected static final String RULE_EXTRA_PROCESSING_KEY = "extraprocessing";

    protected static final String CONFIRM_REMOVE_RULE_KEY =
            REPLACER_BASE_KEY + ".confirmRemoveToken";
    protected static final String FALSE_STRING = "false";
    protected static final String TRUE_STRING = "true";

    protected static final String REPORT_TO_DESC = "Disable Report-To or Report-Uri (CSP, etc)";
    protected static final String REPORT_TO_REGEX = "(?i)report-(?:to|uri)";
    protected static final String REPORT_TO_REPLACEMENT = "report-disabled";

    private static final String NONE_MATCH_DESC = "Require non-cached response (Match)";
    private static final String MODIFIED_SINCE_DESC = "Require non-cached response (Modified)";

    /**
     * The current version of the configurations. Used to keep track of configuration changes
     * between releases, in case changes/updates are needed.
     *
     * <p>It only needs to be incremented for configuration changes (not releases of the add-on).
     *
     * @see #CONFIG_VERSION_KEY
     * @see #updateConfigsImpl(int)
     */
    private static final int CURRENT_CONFIG_VERSION = 1;

    /**
     * The key for the version of the configurations.
     *
     * @see #CURRENT_CONFIG_VERSION
     */
    private static final String CONFIG_VERSION_KEY = REPLACER_BASE_KEY + VERSION_ATTRIBUTE;

    // Order is important here and these are referenced by index during config update
    private static List<ReplacerParamRule> defaultList =
            List.of(
                    new ReplacerParamRule(
                            "Remove CSP",
                            ReplacerParamRule.MatchType.RESP_HEADER,
                            "Content-Security-Policy",
                            false,
                            "",
                            List.of(),
                            false),
                    new ReplacerParamRule(
                            "Remove HSTS",
                            ReplacerParamRule.MatchType.RESP_HEADER,
                            "Strict-Transport-Security",
                            false,
                            "",
                            List.of(),
                            false),
                    new ReplacerParamRule(
                            "Replace User-Agent with shellshock attack",
                            ReplacerParamRule.MatchType.REQ_HEADER,
                            "User-Agent",
                            false,
                            "() {:;}; /bin/cat /etc/passwd",
                            List.of(),
                            false),
                    new ReplacerParamRule(
                            REPORT_TO_DESC,
                            ReplacerParamRule.MatchType.RESP_HEADER_STR,
                            REPORT_TO_REGEX,
                            true,
                            REPORT_TO_REPLACEMENT,
                            List.of(),
                            false),
                    new ReplacerParamRule(
                            MODIFIED_SINCE_DESC,
                            ReplacerParamRule.MatchType.REQ_HEADER,
                            HttpFieldsNames.IF_MODIFIED_SINCE,
                            false,
                            "",
                            List.of(),
                            false),
                    new ReplacerParamRule(
                            NONE_MATCH_DESC,
                            ReplacerParamRule.MatchType.REQ_HEADER,
                            HttpFieldsNames.IF_NONE_MATCH,
                            false,
                            "",
                            List.of(),
                            false));

    private List<ReplacerParamRule> rules = new ArrayList<>();

    private boolean confirmRemoveToken = true;

    public ReplacerParam() {
        super();
    }

    @Override
    protected void parseImpl() {
        parseReplacerRules();

        this.confirmRemoveToken = getBoolean(CONFIRM_REMOVE_RULE_KEY, true);
    }

    private void parseReplacerRules() {
        try {
            List<HierarchicalConfiguration> fields =
                    ((HierarchicalConfiguration) getConfig()).configurationsAt(ALL_RULES_KEY);
            this.rules = new ArrayList<>(fields.size());
            List<String> tempTokensNames = new ArrayList<>(fields.size());
            for (HierarchicalConfiguration sub : fields) {
                String desc = sub.getString(RULE_DESCRIPTION_KEY, "");
                if (!"".equals(desc) && !tempTokensNames.contains(desc)) {
                    boolean enabled = sub.getBoolean(RULE_ENABLED_KEY, true);
                    boolean regex = sub.getBoolean(RULE_REGEX_KEY, true);
                    boolean extraProcessing = sub.getBoolean(RULE_EXTRA_PROCESSING_KEY, false);
                    String matchStr = sub.getString(RULE_MATCH_STRING_KEY, "");
                    MatchType matchType =
                            MatchType.valueOf(
                                    sub.getString(
                                                    RULE_MATCH_TYPE_KEY,
                                                    MatchType.RESP_BODY_STR.name())
                                            .toUpperCase());
                    String replace = sub.getString(RULE_REPLACEMENT_KEY, "");
                    String initStr = sub.getString(RULE_INITIATORS_KEY, "");
                    List<Integer> initList = null;
                    if (!StringUtils.isEmpty(initStr)) {
                        initList = new ArrayList<>();
                        String[] initStrArray =
                                initStr.replace("[", "").replace("]", "").split(",");
                        for (String str : initStrArray) {
                            try {
                                initList.add(Integer.parseInt(str.trim()));
                            } catch (NumberFormatException e) {
                                LOGGER.error(
                                        "Error while loading global replacement rule: {}",
                                        e.getMessage(),
                                        e);
                            }
                        }
                    }
                    this.rules.add(
                            new ReplacerParamRule(
                                    desc,
                                    sub.getString(RULE_URL_KEY, ""),
                                    matchType,
                                    matchStr,
                                    regex,
                                    replace,
                                    initList,
                                    enabled,
                                    extraProcessing));
                    tempTokensNames.add(desc);
                }
            }
        } catch (ConversionException e) {
            LOGGER.error("Error while loading global replacement rules: {}", e.getMessage(), e);
            this.rules = new ArrayList<>(defaultList.size());
        }

        if (this.rules.isEmpty()) {
            for (ReplacerParamRule geu : defaultList) {
                this.rules.add(new ReplacerParamRule(geu));
            }
        }
    }

    public List<ReplacerParamRule> getRules() {
        return rules;
    }

    public void setRules(List<ReplacerParamRule> rules) {
        this.rules = new ArrayList<>(rules);
        saveRules();
    }

    public void clearRules() {
        this.rules = new ArrayList<>();
        saveRules();
    }

    private void saveRules() {

        ((HierarchicalConfiguration) getConfig()).clearTree(ALL_RULES_KEY);

        ArrayList<String> enabledTokens = new ArrayList<>(rules.size());
        for (int i = 0, size = rules.size(); i < size; ++i) {
            String elementBaseKey = ALL_RULES_KEY + "(" + i + ").";
            ReplacerParamRule rule = rules.get(i);

            getConfig().setProperty(elementBaseKey + RULE_DESCRIPTION_KEY, rule.getDescription());
            getConfig().setProperty(elementBaseKey + RULE_URL_KEY, rule.getUrl());
            getConfig()
                    .setProperty(
                            elementBaseKey + RULE_ENABLED_KEY, Boolean.valueOf(rule.isEnabled()));
            getConfig()
                    .setProperty(elementBaseKey + RULE_MATCH_TYPE_KEY, rule.getMatchType().name());
            getConfig().setProperty(elementBaseKey + RULE_MATCH_STRING_KEY, rule.getMatchString());
            getConfig()
                    .setProperty(
                            elementBaseKey + RULE_REGEX_KEY, Boolean.valueOf(rule.isMatchRegex()));
            getConfig().setProperty(elementBaseKey + RULE_REPLACEMENT_KEY, rule.getReplacement());
            getConfig()
                    .setProperty(
                            elementBaseKey + RULE_EXTRA_PROCESSING_KEY,
                            Boolean.valueOf(rule.isTokenProcessingEnabled()));

            List<Integer> initiators = rule.getInitiators();
            if (initiators == null || initiators.isEmpty()) {
                getConfig().setProperty(elementBaseKey + RULE_INITIATORS_KEY, "");
            } else {
                getConfig()
                        .setProperty(elementBaseKey + RULE_INITIATORS_KEY, initiators.toString());
            }

            if (rule.isEnabled()) {
                enabledTokens.add(rule.getDescription());
            }
        }

        enabledTokens.trimToSize();
    }

    public ReplacerParamRule getRule(String desc) {
        for (ReplacerParamRule rule : rules) {
            if (rule.getDescription().equals(desc)) {
                return rule;
            }
        }
        return null;
    }

    public boolean setEnabled(String desc, boolean enabled) {
        ReplacerParamRule rule = this.getRule(desc);
        if (rule != null) {
            rule.setEnabled(enabled);
            this.saveRules();
            return true;
        }
        return false;
    }

    public void addRule(ReplacerParamRule rule) {
        this.rules.add(rule);
        this.saveRules();
    }

    public boolean removeRule(String desc) {
        ReplacerParamRule rule = this.getRule(desc);
        if (rule != null) {
            this.rules.remove(rule);
            this.saveRules();
            return true;
        }
        return false;
    }

    @ZapApiIgnore
    public boolean isConfirmRemoveToken() {
        return this.confirmRemoveToken;
    }

    @ZapApiIgnore
    public void setConfirmRemoveToken(boolean confirmRemove) {
        this.confirmRemoveToken = confirmRemove;
        getConfig().setProperty(CONFIRM_REMOVE_RULE_KEY, Boolean.valueOf(confirmRemoveToken));
    }

    @Override
    protected String getConfigVersionKey() {
        return CONFIG_VERSION_KEY;
    }

    @Override
    protected int getCurrentVersion() {
        return CURRENT_CONFIG_VERSION;
    }

    @Override
    @SuppressWarnings("fallthrough")
    protected void updateConfigsImpl(int fileVersion) {
        switch (fileVersion) {
            case NO_CONFIG_VERSION:
                // Handle unversioned to versioned update
                parseReplacerRules();
                addIfAbsent(3);
                addIfAbsent(4);
                addIfAbsent(5);
                // Fallthrough
            default:
        }
    }

    private void addIfAbsent(int index) {
        ReplacerParamRule rule = defaultList.get(index);

        if (getRule(rule.getDescription()) == null) {
            addRule(rule);
        }
    }
}
