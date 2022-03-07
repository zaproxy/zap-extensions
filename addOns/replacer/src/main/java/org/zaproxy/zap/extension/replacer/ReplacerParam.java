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
import org.apache.commons.lang.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.common.AbstractParam;
import org.zaproxy.zap.extension.api.ZapApiIgnore;
import org.zaproxy.zap.extension.replacer.ReplacerParamRule.MatchType;

public class ReplacerParam extends AbstractParam {

    private static final Logger logger = LogManager.getLogger(ReplacerParam.class);

    private static final String REPLACER_BASE_KEY = "replacer";

    private static final String ALL_RULES_KEY = REPLACER_BASE_KEY + ".full_list";

    private static final String RULE_DESCRIPTION_KEY = "description";
    private static final String RULE_ENABLED_KEY = "enabled";
    private static final String RULE_MATCH_STRING_KEY = "matchstr";
    private static final String RULE_MATCH_TYPE_KEY = "matchtype";
    private static final String RULE_REGEX_KEY = "regex";
    private static final String RULE_REPLACEMENT_KEY = "replacement";
    private static final String RULE_INITIATORS_KEY = "initiators";

    private static final String CONFIRM_REMOVE_RULE_KEY = REPLACER_BASE_KEY + ".confirmRemoveToken";
    private static final String FALSE_STRING = "false";

    private static ArrayList<ReplacerParamRule> defaultList = new ArrayList<>();

    private List<ReplacerParamRule> rules = new ArrayList<>();

    private boolean confirmRemoveToken = true;

    /** Fills in the list of rules which will be added if there are none configured. */
    private void setDefaultList() {
        final String[][] defaultListArray = {
            {
                "Remove CSP",
                ReplacerParamRule.MatchType.RESP_HEADER.name(),
                "Content-Security-Policy",
                "",
                FALSE_STRING,
                "",
                FALSE_STRING
            },
            {
                "Remove HSTS",
                ReplacerParamRule.MatchType.RESP_HEADER.name(),
                "Strict-Transport-Security",
                "",
                FALSE_STRING,
                "",
                FALSE_STRING
            },
            {
                "Replace User-Agent with shellshock attack",
                ReplacerParamRule.MatchType.REQ_HEADER.name(),
                "User-Agent",
                "() {:;}; /bin/cat /etc/passwd",
                FALSE_STRING,
                "",
                FALSE_STRING
            }
        };

        for (String[] row : defaultListArray) {
            boolean regex = row[4].equalsIgnoreCase("true");
            boolean enabled = row[6].equalsIgnoreCase("true");
            defaultList.add(
                    new ReplacerParamRule(
                            row[0],
                            MatchType.valueOf(row[1]),
                            row[2],
                            regex,
                            row[3],
                            null,
                            enabled));
        }
    }

    public ReplacerParam() {
        super();
        setDefaultList();
    }

    @Override
    protected void parse() {
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
                                logger.error(
                                        "Error while loading global repacement rule: {}",
                                        e.getMessage(),
                                        e);
                            }
                        }
                    }
                    this.rules.add(
                            new ReplacerParamRule(
                                    desc, matchType, matchStr, regex, replace, initList, enabled));
                    tempTokensNames.add(desc);
                }
            }
        } catch (ConversionException e) {
            logger.error("Error while loading global repacement rules: {}", e.getMessage(), e);
            this.rules = new ArrayList<>(defaultList.size());
        }

        if (this.rules.isEmpty()) {
            for (ReplacerParamRule geu : defaultList) {
                this.rules.add(new ReplacerParamRule(geu));
            }
        }

        this.confirmRemoveToken = getBoolean(CONFIRM_REMOVE_RULE_KEY, true);
    }

    public List<ReplacerParamRule> getRules() {
        return rules;
    }

    public void setRules(List<ReplacerParamRule> rules) {
        this.rules = new ArrayList<>(rules);
        saveRules();
    }

    private void saveRules() {

        ((HierarchicalConfiguration) getConfig()).clearTree(ALL_RULES_KEY);

        ArrayList<String> enabledTokens = new ArrayList<>(rules.size());
        for (int i = 0, size = rules.size(); i < size; ++i) {
            String elementBaseKey = ALL_RULES_KEY + "(" + i + ").";
            ReplacerParamRule rule = rules.get(i);

            getConfig().setProperty(elementBaseKey + RULE_DESCRIPTION_KEY, rule.getDescription());
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
}
