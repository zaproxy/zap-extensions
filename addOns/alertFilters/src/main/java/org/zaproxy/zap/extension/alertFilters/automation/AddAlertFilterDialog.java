/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.zap.extension.alertFilters.automation;

import java.awt.Component;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;
import javax.swing.JTextField;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.automation.jobs.JobUtils;
import org.zaproxy.zap.extension.alertFilters.ExtensionAlertFilters;
import org.zaproxy.zap.extension.alertFilters.automation.AlertFilterJob.Risk;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.StandardFieldsDialog;

@SuppressWarnings("serial")
public class AddAlertFilterDialog extends StandardFieldsDialog {

    private static final long serialVersionUID = 1L;

    private static final String TITLE = "alertFilters.automation.dialog.addfilter.title";
    private static final String RULE_PARAM = "alertFilters.automation.dialog.addfilter.rule";
    private static final String CONTEXT_PARAM = "alertFilters.automation.dialog.addfilter.context";
    private static final String NEW_RISK_PARAM = "alertFilters.automation.dialog.addfilter.newrisk";
    private static final String PARAM_PARAM = "alertFilters.automation.dialog.addfilter.param";
    private static final String PARAM_REGEX_PARAM =
            "alertFilters.automation.dialog.addfilter.paramregex";
    private static final String URL_PARAM = "alertFilters.automation.dialog.addfilter.url";
    private static final String URL_REGEX_PARAM =
            "alertFilters.automation.dialog.addfilter.urlregex";
    private static final String ATTACK_PARAM = "alertFilters.automation.dialog.addfilter.attack";
    private static final String ATTACK_REGEX_PARAM =
            "alertFilters.automation.dialog.addfilter.attackregex";
    private static final String EVIDENCE_PARAM =
            "alertFilters.automation.dialog.addfilter.evidence";
    private static final String EVIDENCE_REGEX_PARAM =
            "alertFilters.automation.dialog.addfilter.evidenceregex";

    private AlertFilterJob.AlertFilterData rule;
    private boolean addFilter = false;
    private int tableIndex;
    private AlertFilterJob job;
    private AlertFilterTableModel model;

    public AddAlertFilterDialog(AlertFilterJob job, AlertFilterTableModel model) {
        this(job, model, null, -1);
    }

    public AddAlertFilterDialog(
            AlertFilterJob job,
            AlertFilterTableModel model,
            AlertFilterJob.AlertFilterData rule,
            int tableIndex) {
        super(View.getSingleton().getMainFrame(), TITLE, DisplayUtils.getScaledDimension(550, 450));
        if (rule == null) {
            rule = new AlertFilterJob.AlertFilterData();
            this.addFilter = true;
        }
        this.rule = rule;
        this.job = job;
        this.model = model;
        this.tableIndex = tableIndex;

        this.addComboField(
                RULE_PARAM,
                ExtensionAlertFilters.getAllRuleNames(),
                ExtensionAlertFilters.getRuleNameForId(rule.getRuleId()));

        List<String> contextNames = this.job.getEnv().getContextNames();
        // Add blank option
        contextNames.add(0, "");
        this.addComboField(CONTEXT_PARAM, contextNames, rule.getContext());

        this.addComboField(
                NEW_RISK_PARAM,
                Arrays.stream(Risk.values()).map(Risk::getI18nString).toArray(String[]::new),
                rule.getNewRisk());

        // Cannot select the node as it might not be present in the Sites tree
        this.addNodeSelectField(URL_PARAM, null, true, false);
        Component urlField = this.getField(URL_PARAM);
        if (urlField instanceof JTextField) {
            ((JTextField) urlField).setText(rule.getUrl());
        }
        this.addCheckBoxField(URL_REGEX_PARAM, JobUtils.unBox(rule.getUrlRegex()));

        this.addTextField(PARAM_PARAM, rule.getParameter());
        this.addCheckBoxField(PARAM_REGEX_PARAM, JobUtils.unBox(rule.getParameterRegex()));

        this.addTextField(ATTACK_PARAM, rule.getAttack());
        this.addCheckBoxField(ATTACK_REGEX_PARAM, JobUtils.unBox(rule.getAttackRegex()));

        this.addTextField(EVIDENCE_PARAM, rule.getEvidence());
        this.addCheckBoxField(EVIDENCE_REGEX_PARAM, JobUtils.unBox(rule.getEvidenceRegex()));
    }

    @Override
    public void save() {
        String ruleName = this.getStringValue(RULE_PARAM);
        rule.setRuleId(ExtensionAlertFilters.getIdForRuleName(ruleName));
        rule.setRuleName(ruleName);
        rule.setContext(this.getStringValue(CONTEXT_PARAM));
        rule.setNewRisk(Risk.getRiskFromI18n(this.getStringValue(NEW_RISK_PARAM)).toString());
        rule.setParameter(this.getStringValue(PARAM_PARAM));
        rule.setParameterRegex(this.getBoolValue(PARAM_REGEX_PARAM));
        rule.setUrl(this.getStringValue(URL_PARAM));
        rule.setUrlRegex(this.getBoolValue(URL_REGEX_PARAM));
        rule.setAttack(this.getStringValue(ATTACK_PARAM));
        rule.setAttackRegex(this.getBoolValue(ATTACK_REGEX_PARAM));
        rule.setEvidence(this.getStringValue(EVIDENCE_PARAM));
        rule.setEvidenceRegex(this.getBoolValue(EVIDENCE_REGEX_PARAM));

        if (addFilter) {
            this.model.add(rule);
        } else {
            this.model.update(tableIndex, rule);
        }
    }

    @Override
    public String validateFields() {
        if (!isValid(URL_REGEX_PARAM, URL_PARAM, true)) {
            return Constant.messages.getString("alertFilters.dialog.error.badregex.url");
        }
        if (!isValid(PARAM_REGEX_PARAM, PARAM_PARAM, true)) {
            return Constant.messages.getString("alertFilters.dialog.error.badregex.param");
        }
        if (!isValid(ATTACK_REGEX_PARAM, ATTACK_PARAM, false)) {
            return Constant.messages.getString("alertFilters.dialog.error.badregex.attack");
        }
        if (!isValid(EVIDENCE_REGEX_PARAM, EVIDENCE_PARAM, false)) {
            return Constant.messages.getString("alertFilters.dialog.error.badregex.evidence");
        }
        return null;
    }

    private boolean isValid(String isBoolParam, String strParam, boolean canContainEnvVars) {
        if (!this.getBoolValue(isBoolParam)) {
            // Anything is allowed
            return true;
        }
        String str = this.getStringValue(strParam);
        if (canContainEnvVars && str.contains("${")) {
            // Can't do any more checking as the env var will break the regex checking
            return true;
        }
        try {
            Pattern.compile(str);
        } catch (Exception e) {
            return false;
        }
        return true;
    }
}
