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
package org.zaproxy.addon.automation.gui;

import java.util.ArrayList;
import java.util.List;
import javax.swing.JButton;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.zaproxy.addon.automation.jobs.ActiveScanJob;
import org.zaproxy.addon.automation.jobs.ActiveScanJob.Parameters;
import org.zaproxy.addon.automation.jobs.JobUtils;
import org.zaproxy.addon.automation.jobs.PolicyDefinition.Rule;
import org.zaproxy.zap.utils.DisplayUtils;

@SuppressWarnings("serial")
public class ActiveScanJobDialog extends ActiveScanPolicyDialog {

    private static final long serialVersionUID = 1L;

    private static final String[] TAB_LABELS = {
        "automation.dialog.tab.params",
        "automation.dialog.ascan.tab.policydefaults",
        "automation.dialog.ascan.tab.policyrules",
        "automation.dialog.ascan.tab.adv"
    };

    private static final String TITLE = "automation.dialog.ascan.title";
    private static final String NAME_PARAM = "automation.dialog.all.name";
    private static final String CONTEXT_PARAM = "automation.dialog.ascan.context";
    private static final String USER_PARAM = "automation.dialog.all.user";
    private static final String POLICY_PARAM = "automation.dialog.ascan.policy";
    private static final String MAX_RULE_DURATION_PARAM = "automation.dialog.ascan.maxruleduration";
    private static final String MAX_SCAN_DURATION_PARAM = "automation.dialog.ascan.maxscanduration";
    private static final String MAX_ALERTS_PER_RULE_PARAM =
            "automation.dialog.ascan.maxalertsperrule";
    private static final String FIELD_ADVANCED = "automation.dialog.ascan.advanced";

    private static final String DELAY_IN_MS_PARAM = "automation.dialog.ascan.delayinms";
    private static final String THREADS_PER_HOST_PARAM = "automation.dialog.ascan.threads";
    private static final String ADD_QUERY_PARAM = "automation.dialog.ascan.addquery";
    private static final String HANDLE_ANTI_CSRF_PARAM = "automation.dialog.ascan.handleanticsrf";
    private static final String INJECT_PLUGIN_ID_PARAM = "automation.dialog.ascan.injectid";
    private static final String SCAN_HEADERS_PARAM = "automation.dialog.ascan.scanheaders";

    private ActiveScanJob job;

    public ActiveScanJobDialog(ActiveScanJob job) {
        super(TITLE, DisplayUtils.getScaledDimension(500, 400), TAB_LABELS);
        this.job = job;

        this.addTextField(0, NAME_PARAM, this.job.getData().getName());
        List<String> contextNames = this.job.getEnv().getContextNames();
        // Add blank option
        contextNames.add(0, "");
        this.addComboField(0, CONTEXT_PARAM, contextNames, this.job.getParameters().getContext());

        List<String> users = job.getEnv().getAllUserNames();
        // Add blank option
        users.add(0, "");
        this.addComboField(0, USER_PARAM, users, this.job.getData().getParameters().getUser());

        this.addTextField(0, POLICY_PARAM, this.job.getParameters().getPolicy());
        this.addNumberField(
                0,
                MAX_RULE_DURATION_PARAM,
                0,
                Integer.MAX_VALUE,
                JobUtils.unBox(job.getParameters().getMaxRuleDurationInMins()));
        this.addNumberField(
                0,
                MAX_SCAN_DURATION_PARAM,
                0,
                Integer.MAX_VALUE,
                JobUtils.unBox(job.getParameters().getMaxScanDurationInMins()));
        addNumberField(
                0,
                MAX_ALERTS_PER_RULE_PARAM,
                0,
                Integer.MAX_VALUE,
                JobUtils.unBox(job.getParameters().getMaxAlertsPerRule()));
        this.addCheckBoxField(0, FIELD_ADVANCED, advOptionsSet());
        this.addFieldListener(FIELD_ADVANCED, e -> setAdvancedTabs(getBoolValue(FIELD_ADVANCED)));

        this.addPadding(0);

        String thresholdName =
                JobUtils.thresholdToI18n(job.getData().getPolicyDefinition().getDefaultThreshold());
        if (thresholdName.isEmpty()) {
            thresholdName = JobUtils.thresholdToI18n(AlertThreshold.MEDIUM.name());
        }
        String strengthName =
                JobUtils.strengthToI18n(job.getData().getPolicyDefinition().getDefaultStrength());
        if (strengthName.isEmpty()) {
            strengthName = JobUtils.strengthToI18n(AttackStrength.MEDIUM.name());
        }

        List<String> allthresholds = new ArrayList<>();

        for (AlertThreshold at : AlertThreshold.values()) {
            if (AlertThreshold.DEFAULT.equals(at)) {
                continue;
            }
            allthresholds.add(JobUtils.thresholdToI18n(at.name()));
        }

        this.addComboField(1, DEFAULT_THRESHOLD_PARAM, allthresholds, thresholdName);

        List<String> allstrengths = new ArrayList<>();

        for (AttackStrength at : AttackStrength.values()) {
            if (AttackStrength.DEFAULT.equals(at)) {
                continue;
            }
            allstrengths.add(JobUtils.strengthToI18n(at.name()));
        }

        this.addComboField(1, DEFAULT_STRENGTH_PARAM, allstrengths, strengthName);

        this.addPadding(1);

        List<JButton> buttons = new ArrayList<>();
        buttons.add(getAddButton());
        buttons.add(getModifyButton());
        buttons.add(getRemoveButton());

        this.addTableField(2, getRulesTable(), buttons);

        this.addNumberField(
                3,
                DELAY_IN_MS_PARAM,
                0,
                Integer.MAX_VALUE,
                JobUtils.unBox(job.getParameters().getDelayInMs()));
        this.addNumberField(
                3,
                THREADS_PER_HOST_PARAM,
                1,
                Integer.MAX_VALUE,
                JobUtils.unBox(job.getParameters().getThreadPerHost()));
        this.addCheckBoxField(
                3, ADD_QUERY_PARAM, JobUtils.unBox(job.getParameters().getAddQueryParam()));
        this.addCheckBoxField(
                3,
                HANDLE_ANTI_CSRF_PARAM,
                JobUtils.unBox(job.getParameters().getHandleAntiCSRFTokens()));
        this.addCheckBoxField(
                3,
                INJECT_PLUGIN_ID_PARAM,
                JobUtils.unBox(job.getParameters().getInjectPluginIdInHeader()));
        this.addCheckBoxField(
                3,
                SCAN_HEADERS_PARAM,
                JobUtils.unBox(job.getParameters().getScanHeadersAllRequests()));

        this.addPadding(3);

        setAdvancedTabs(getBoolValue(FIELD_ADVANCED));
    }

    private boolean advOptionsSet() {
        Parameters params = this.job.getParameters();
        return params.getDelayInMs() != null
                || params.getThreadPerHost() != null
                || params.getAddQueryParam() != null
                || params.getHandleAntiCSRFTokens() != null
                || params.getInjectPluginIdInHeader() != null
                || params.getScanHeadersAllRequests() != null;
    }

    private void setAdvancedTabs(boolean visible) {
        // Show/hide the advanced tab
        this.setTabsVisible(new String[] {"automation.dialog.ascan.tab.adv"}, visible);
    }

    @Override
    public void save() {
        this.job.getData().setName(this.getStringValue(NAME_PARAM));
        this.job.getParameters().setContext(this.getStringValue(CONTEXT_PARAM));
        this.job.getParameters().setUser(this.getStringValue(USER_PARAM));
        this.job.getParameters().setPolicy(this.getStringValue(POLICY_PARAM));
        this.job
                .getParameters()
                .setMaxRuleDurationInMins(this.getIntValue(MAX_RULE_DURATION_PARAM));
        this.job
                .getParameters()
                .setMaxScanDurationInMins(this.getIntValue(MAX_SCAN_DURATION_PARAM));
        job.getParameters().setMaxAlertsPerRule(getIntValue(MAX_ALERTS_PER_RULE_PARAM));

        this.job
                .getData()
                .getPolicyDefinition()
                .setDefaultStrength(
                        JobUtils.i18nToStrength(this.getStringValue(DEFAULT_STRENGTH_PARAM)));
        this.job
                .getData()
                .getPolicyDefinition()
                .setDefaultThreshold(
                        JobUtils.i18nToThreshold(this.getStringValue(DEFAULT_THRESHOLD_PARAM)));

        if (JobUtils.unBox(getBoolValue(FIELD_ADVANCED))) {
            this.job.getParameters().setDelayInMs(this.getIntValue(DELAY_IN_MS_PARAM));
            this.job.getParameters().setThreadPerHost(this.getIntValue(THREADS_PER_HOST_PARAM));
            this.job.getParameters().setAddQueryParam(this.getBoolValue(ADD_QUERY_PARAM));
            this.job
                    .getParameters()
                    .setHandleAntiCSRFTokens(this.getBoolValue(HANDLE_ANTI_CSRF_PARAM));
            this.job
                    .getParameters()
                    .setInjectPluginIdInHeader(this.getBoolValue(INJECT_PLUGIN_ID_PARAM));
            this.job
                    .getParameters()
                    .setScanHeadersAllRequests(this.getBoolValue(SCAN_HEADERS_PARAM));
        } else {
            this.job.getParameters().setDelayInMs(null);
            this.job.getParameters().setThreadPerHost(null);
            this.job.getParameters().setAddQueryParam(null);
            this.job.getParameters().setHandleAntiCSRFTokens(null);
            this.job.getParameters().setInjectPluginIdInHeader(null);
            this.job.getParameters().setScanHeadersAllRequests(null);
        }
        this.job.getData().getPolicyDefinition().setRules(this.getRulesModel().getRules());
        this.job.resetAndSetChanged();
    }

    @Override
    public String validateFields() {
        // Nothing to do
        return null;
    }

    @Override
    protected List<Rule> getRules() {
        return job.getData().getPolicyDefinition().getRules();
    }
}
