/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2019 The ZAP Development Team
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
package org.zaproxy.zap.extension.alertFilters;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.apache.commons.configuration.ConversionException;
import org.apache.commons.configuration.HierarchicalConfiguration;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.zap.common.VersionedAbstractParam;

public class GlobalAlertFilterParam extends VersionedAbstractParam {

    private static final Logger logger = LogManager.getLogger(GlobalAlertFilterParam.class);

    /**
     * The version of the configurations. Used to keep track of configurations changes between
     * releases, if updates are needed.
     *
     * <p>It only needs to be updated for configurations changes (not releases of the add-on).
     */
    private static final int PARAM_CURRENT_VERSION = 1;

    private static final String GLOBAL_ALERT_FILTERS_BASE_KEY = "globalalertfilter";

    private static final String ALL_ALERT_FILTERS_KEY =
            GLOBAL_ALERT_FILTERS_BASE_KEY + ".filters.filter";

    private static final String FILTER_RULE_ID_KEY = "ruleid";
    private static final String FILTER_URL_KEY = "url";
    private static final String FILTER_URL_IS_REGEX_KEY = "urlregex";
    private static final String FILTER_NEW_RISK_KEY = "newrisk";
    private static final String FILTER_PARAMETER_KEY = "param";
    private static final String FILTER_PARAMETER_IS_REGEX_KEY = "paramregex";
    private static final String FILTER_ATTACK_KEY = "attack";
    private static final String FILTER_ATTACK_IS_REGEX_KEY = "attackregex";
    private static final String FILTER_EVIDENCE_KEY = "evidence";
    private static final String FILTER_EVIDENCE_IS_REGEX_KEY = "evidenceregex";
    private static final String FILTER_ENABLED_KEY = "enabled";

    private static final String CONFIRM_REMOVE_FILTER_KEY =
            GLOBAL_ALERT_FILTERS_BASE_KEY + ".confirmRemoveFilter";

    private Set<AlertFilter> alertFilters = null;

    private boolean confirmRemoveFilter = true;

    public GlobalAlertFilterParam() {}

    public Set<AlertFilter> getGlobalAlertFilters() {
        return alertFilters;
    }

    public void deleteGlobalAlertFilters() {
        alertFilters.clear();
        this.saveGlobalAlertFilters();
    }

    public void setGlobalAlertFilters(List<AlertFilter> filters) {
        this.alertFilters = new HashSet<>(filters);
        this.saveGlobalAlertFilters();
    }

    private void saveGlobalAlertFilters() {
        ((HierarchicalConfiguration) getConfig()).clearTree(ALL_ALERT_FILTERS_KEY);

        int i = 0;
        for (AlertFilter filter : alertFilters) {
            String elementBaseKey = ALL_ALERT_FILTERS_KEY + "(" + i + ").";

            getConfig().setProperty(elementBaseKey + FILTER_RULE_ID_KEY, filter.getRuleId());
            getConfig().setProperty(elementBaseKey + FILTER_NEW_RISK_KEY, filter.getNewRisk());
            getConfig().setProperty(elementBaseKey + FILTER_URL_KEY, filter.getUrl());
            getConfig().setProperty(elementBaseKey + FILTER_URL_IS_REGEX_KEY, filter.isUrlRegex());
            getConfig().setProperty(elementBaseKey + FILTER_PARAMETER_KEY, filter.getParameter());
            getConfig()
                    .setProperty(
                            elementBaseKey + FILTER_PARAMETER_IS_REGEX_KEY,
                            filter.isParameterRegex());
            getConfig().setProperty(elementBaseKey + FILTER_ATTACK_KEY, filter.getAttack());
            getConfig()
                    .setProperty(
                            elementBaseKey + FILTER_ATTACK_IS_REGEX_KEY, filter.isAttackRegex());
            getConfig().setProperty(elementBaseKey + FILTER_EVIDENCE_KEY, filter.getEvidence());
            getConfig()
                    .setProperty(
                            elementBaseKey + FILTER_EVIDENCE_IS_REGEX_KEY,
                            filter.isEvidenceRegex());
            getConfig().setProperty(elementBaseKey + FILTER_ENABLED_KEY, filter.isEnabled());
            i++;
        }
    }

    public boolean addAlertFilter(AlertFilter alertFilter) {
        if (alertFilter == null) {
            return false;
        }

        if (this.alertFilters.add(alertFilter)) {
            this.saveGlobalAlertFilters();
            return true;
        }
        return false;
    }

    public boolean removeFilter(AlertFilter alertFilter) {
        if (alertFilter == null) {
            return false;
        }
        if (alertFilters.remove(alertFilter)) {
            this.saveGlobalAlertFilters();
            return true;
        }
        return false;
    }

    public boolean isConfirmRemoveFilter() {
        return this.confirmRemoveFilter;
    }

    public void setConfirmRemoveFilter(boolean confirmRemove) {
        this.confirmRemoveFilter = confirmRemove;
        getConfig().setProperty(CONFIRM_REMOVE_FILTER_KEY, confirmRemoveFilter);
    }

    @Override
    protected void parseImpl() {
        try {
            List<HierarchicalConfiguration> fields =
                    ((HierarchicalConfiguration) getConfig())
                            .configurationsAt(ALL_ALERT_FILTERS_KEY);
            this.alertFilters = new HashSet<>();
            for (HierarchicalConfiguration sub : fields) {
                alertFilters.add(
                        new AlertFilter(
                                -1,
                                sub.getInt(FILTER_RULE_ID_KEY),
                                sub.getInt(FILTER_NEW_RISK_KEY),
                                sub.getString(FILTER_URL_KEY, null),
                                sub.getBoolean(FILTER_URL_IS_REGEX_KEY, false),
                                sub.getString(FILTER_PARAMETER_KEY, null),
                                sub.getBoolean(FILTER_PARAMETER_IS_REGEX_KEY, false),
                                sub.getString(FILTER_ATTACK_KEY, null),
                                sub.getBoolean(FILTER_ATTACK_IS_REGEX_KEY, false),
                                sub.getString(FILTER_EVIDENCE_KEY, null),
                                sub.getBoolean(FILTER_EVIDENCE_IS_REGEX_KEY, false),
                                sub.getBoolean(FILTER_ENABLED_KEY, false)));
            }
        } catch (ConversionException e) {
            logger.error("Error while loading global alert filters: {}", e.getMessage(), e);
        }

        this.confirmRemoveFilter = getBoolean(CONFIRM_REMOVE_FILTER_KEY, true);
    }

    @Override
    protected String getConfigVersionKey() {
        return GLOBAL_ALERT_FILTERS_BASE_KEY + VERSION_ATTRIBUTE;
    }

    @Override
    protected int getCurrentVersion() {
        return PARAM_CURRENT_VERSION;
    }

    @Override
    protected void updateConfigsImpl(int fileVersion) {}
}
