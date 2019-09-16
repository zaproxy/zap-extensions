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

import java.util.ArrayList;
import java.util.List;
import org.apache.commons.configuration.ConversionException;
import org.apache.commons.configuration.HierarchicalConfiguration;
import org.apache.log4j.Logger;
import org.parosproxy.paros.common.AbstractParam;
import org.zaproxy.zap.extension.api.ZapApiIgnore;

public class GlobalAlertFilterParam extends AbstractParam {

    private static final Logger logger = Logger.getLogger(GlobalAlertFilterParam.class);

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

    private List<AlertFilter> alertFilters = null;

    private boolean confirmRemoveFilter = true;

    public GlobalAlertFilterParam() {}

    @Override
    protected void parse() {
        try {
            List<HierarchicalConfiguration> fields =
                    ((HierarchicalConfiguration) getConfig())
                            .configurationsAt(ALL_ALERT_FILTERS_KEY);
            this.alertFilters = new ArrayList<>(fields.size());
            for (HierarchicalConfiguration sub : fields) {
                alertFilters.add(
                        new AlertFilter(
                                -1,
                                sub.getInt(FILTER_RULE_ID_KEY),
                                sub.getInt(FILTER_NEW_RISK_KEY),
                                sub.getString(FILTER_URL_KEY),
                                sub.getBoolean(FILTER_URL_IS_REGEX_KEY),
                                sub.getString(FILTER_PARAMETER_KEY),
                                sub.getBoolean(FILTER_PARAMETER_IS_REGEX_KEY),
                                sub.getString(FILTER_ATTACK_KEY),
                                sub.getBoolean(FILTER_ATTACK_IS_REGEX_KEY),
                                sub.getString(FILTER_EVIDENCE_KEY),
                                sub.getBoolean(FILTER_EVIDENCE_IS_REGEX_KEY),
                                sub.getBoolean(FILTER_ENABLED_KEY)));
            }
        } catch (ConversionException e) {
            logger.error("Error while loading global alert filters: " + e.getMessage(), e);
        }

        this.confirmRemoveFilter = getBoolean(CONFIRM_REMOVE_FILTER_KEY, true);
    }

    @ZapApiIgnore
    public List<AlertFilter> getGlobalAlertFilters() {
        return alertFilters;
    }

    @ZapApiIgnore
    public void setGlobalAlertFilters(List<AlertFilter> filters) {
        this.alertFilters = new ArrayList<>(filters);

        ((HierarchicalConfiguration) getConfig()).clearTree(ALL_ALERT_FILTERS_KEY);

        for (int i = 0, size = filters.size(); i < size; ++i) {
            String elementBaseKey = ALL_ALERT_FILTERS_KEY + "(" + i + ").";
            AlertFilter filter = filters.get(i);

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
        }
    }

    public void addAlertFilter(AlertFilter alertFilter) {
        if (alertFilter == null) {
            return;
        }

        if (alertFilters.stream().noneMatch(filter -> alertFilter.equals(filter))) {
            this.alertFilters.add(alertFilter);
        }
    }

    public void removeFilter(AlertFilter alertFilter) {
        if (alertFilter == null) {
            return;
        }
        alertFilters.remove(alertFilter);
    }

    @ZapApiIgnore
    public boolean isConfirmRemoveFilter() {
        return this.confirmRemoveFilter;
    }

    @ZapApiIgnore
    public void setConfirmRemoveFilter(boolean confirmRemove) {
        this.confirmRemoveFilter = confirmRemove;
        getConfig().setProperty(CONFIRM_REMOVE_FILTER_KEY, confirmRemoveFilter);
    }
}
