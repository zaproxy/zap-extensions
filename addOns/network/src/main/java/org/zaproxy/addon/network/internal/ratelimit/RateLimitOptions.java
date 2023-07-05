/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.addon.network.internal.ratelimit;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.apache.commons.configuration.ConversionException;
import org.apache.commons.configuration.HierarchicalConfiguration;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.zap.common.VersionedAbstractParam;

public class RateLimitOptions extends VersionedAbstractParam {
    private static final Logger LOGGER = LogManager.getLogger(RateLimitOptions.class);

    /**
     * The current version of the configurations. Used to keep track of configuration changes
     * between releases, in case changes/updates are needed.
     *
     * <p>It only needs to be incremented for configuration changes (not releases of the add-on).
     *
     * @see #CONFIG_VERSION_KEY
     * @see #updateConfigsImpl(int)
     */
    protected static final int CURRENT_CONFIG_VERSION = 1;

    private static final String RATELIMIT_BASE_KEY = "network.ratelimit";

    /**
     * The configuration key for the version of the configurations.
     *
     * @see #CURRENT_CONFIG_VERSION
     */
    private static final String CONFIG_VERSION_KEY = RATELIMIT_BASE_KEY + VERSION_ATTRIBUTE;

    private static final String ALL_RULES_KEY = RATELIMIT_BASE_KEY + ".rules";
    private static final String RULE_KEY = ALL_RULES_KEY + ".rule";

    private static final String RULE_DESCRIPTION_KEY = "description";
    private static final String RULE_ENABLED_KEY = "enabled";
    private static final String RULE_MATCH_STRING_KEY = "matchStr";
    private static final String RULE_REGEX_KEY = "regex";
    private static final String RULE_REQUESTS_PER_SEC_KEY = "reqsPerSec";
    private static final String RULE_GROUP_BY = "groupBy";

    private static final RateLimitRule.GroupBy DEFAULT_GROUP_BY = RateLimitRule.GroupBy.RULE;

    private List<RateLimitRule> rules = new ArrayList<>();

    private Observer observer;

    @Override
    protected int getCurrentVersion() {
        return CURRENT_CONFIG_VERSION;
    }

    @Override
    protected void updateConfigsImpl(int fileVersion) {
        // first version, nothing to update yet
    }

    @Override
    protected String getConfigVersionKey() {
        return CONFIG_VERSION_KEY;
    }

    @Override
    protected void parseImpl() {
        try {
            List<HierarchicalConfiguration> fields =
                    ((HierarchicalConfiguration) getConfig()).configurationsAt(RULE_KEY);
            this.rules = new ArrayList<>(fields.size());
            List<String> descs = new ArrayList<>(fields.size());
            for (HierarchicalConfiguration sub : fields) {
                String desc = sub.getString(RULE_DESCRIPTION_KEY, "");
                if (!"".equals(desc) && !descs.contains(desc)) {
                    boolean enabled = sub.getBoolean(RULE_ENABLED_KEY, true);
                    boolean regex = sub.getBoolean(RULE_REGEX_KEY, true);
                    String matchStr = sub.getString(RULE_MATCH_STRING_KEY, "");
                    int requestsPerSecond = sub.getInt(RULE_REQUESTS_PER_SEC_KEY, 1);
                    RateLimitRule.GroupBy groupBy = getGroupBy(sub);
                    this.rules.add(
                            new RateLimitRule(
                                    desc, matchStr, regex, requestsPerSecond, groupBy, enabled));
                    descs.add(desc);
                }
            }

            fireObserver();
        } catch (ConversionException e) {
            LOGGER.warn("Error while loading rate limit rules: {}", e.getMessage(), e);
            this.rules = new ArrayList<>();
        }
    }

    private static RateLimitRule.GroupBy getGroupBy(HierarchicalConfiguration sub) {
        String value = sub.getString(RULE_GROUP_BY, DEFAULT_GROUP_BY.name());
        try {
            return RateLimitRule.GroupBy.valueOf(value);
        } catch (IllegalArgumentException e) {
            LOGGER.warn("Using default GroupBy, failed to convert from: {}", value);
            return DEFAULT_GROUP_BY;
        }
    }

    public List<RateLimitRule> getRules() {
        return Collections.unmodifiableList(rules);
    }

    public void setRules(List<RateLimitRule> rules) {
        this.rules = new ArrayList<>(rules);
        saveRules();
    }

    private void saveRules() {
        if (getConfig() == null) {
            fireObserver();
            return;
        }

        ((HierarchicalConfiguration) getConfig()).clearTree(ALL_RULES_KEY);

        for (int i = 0, size = rules.size(); i < size; ++i) {
            String elementBaseKey = RULE_KEY + "(" + i + ").";
            RateLimitRule rule = rules.get(i);

            getConfig().setProperty(elementBaseKey + RULE_DESCRIPTION_KEY, rule.getDescription());
            getConfig()
                    .setProperty(
                            elementBaseKey + RULE_ENABLED_KEY, Boolean.valueOf(rule.isEnabled()));
            getConfig().setProperty(elementBaseKey + RULE_MATCH_STRING_KEY, rule.getMatchString());
            getConfig()
                    .setProperty(
                            elementBaseKey + RULE_REGEX_KEY, Boolean.valueOf(rule.isMatchRegex()));
            getConfig()
                    .setProperty(
                            elementBaseKey + RULE_REQUESTS_PER_SEC_KEY,
                            rule.getRequestsPerSecond());
            getConfig().setProperty(elementBaseKey + RULE_GROUP_BY, rule.getGroupBy().name());
        }

        fireObserver();
    }

    public RateLimitRule getRule(String desc) {
        for (RateLimitRule rule : rules) {
            if (rule.getDescription().equals(desc)) {
                return rule;
            }
        }
        return null;
    }

    public boolean setEnabled(String desc, boolean enabled) {
        RateLimitRule rule = this.getRule(desc);
        if (rule != null) {
            rule.setEnabled(enabled);
            this.saveRules();
            return true;
        }
        return false;
    }

    public void addRule(RateLimitRule rule) {
        if (this.rules.stream().anyMatch(r -> r.equivalentTo(rule))) {
            return;
        }
        this.rules.add(rule);
        this.saveRules();
    }

    public boolean removeRule(String desc) {
        RateLimitRule rule = this.getRule(desc);
        if (rule != null) {
            this.rules.remove(rule);
            this.saveRules();
            return true;
        }
        return false;
    }

    public void setObserver(Observer observer) {
        this.observer = observer;
        fireObserver();
    }

    void fireObserver() {
        if (observer != null) {
            observer.configChange(this);
        }
    }

    public interface Observer {
        /** Notify the options have changed. */
        void configChange(RateLimitOptions options);
    }
}
