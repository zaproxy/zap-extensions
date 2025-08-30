/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.zaproxy.addon.automation.jobs.ActiveScanPolicyJob;
import org.zaproxy.addon.automation.jobs.JobUtils;
import org.zaproxy.addon.automation.jobs.PolicyDefinition;
import org.zaproxy.addon.automation.jobs.PolicyDefinition.Rule;
import org.zaproxy.zap.utils.DisplayUtils;

@SuppressWarnings("serial")
public class ActiveScanPolicyJobDialog extends ActiveScanPolicyDialog {

    private static final long serialVersionUID = 1L;

    private static final String[] TAB_LABELS = {
        "automation.dialog.tab.params",
        "automation.dialog.ascan.tab.policydefaults",
        "automation.dialog.ascan.tab.policyalerttags",
        "automation.dialog.ascan.tab.policyrules",
    };

    private static final String TITLE = "automation.dialog.ascanpolicy.title";
    private static final String JOB_NAME_PARAM = "automation.dialog.all.name";
    private static final String POLICY_NAME_PARAM = "automation.dialog.ascanpolicy.name";

    private ActiveScanPolicyJob job;

    public ActiveScanPolicyJobDialog(ActiveScanPolicyJob job) {
        super(TITLE, DisplayUtils.getScaledDimension(500, 400), TAB_LABELS);
        this.job = job;
        int tabIndex = -1;

        this.addTextField(++tabIndex, JOB_NAME_PARAM, this.job.getData().getName());
        this.addTextField(
                tabIndex, POLICY_NAME_PARAM, this.job.getData().getParameters().getName());
        this.addPadding(tabIndex);

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

        this.addComboField(++tabIndex, DEFAULT_THRESHOLD_PARAM, allthresholds, thresholdName);

        List<String> allstrengths = new ArrayList<>();

        for (AttackStrength at : AttackStrength.values()) {
            if (AttackStrength.DEFAULT.equals(at)) {
                continue;
            }
            allstrengths.add(JobUtils.strengthToI18n(at.name()));
        }

        this.addComboField(tabIndex, DEFAULT_STRENGTH_PARAM, allstrengths, strengthName);

        this.addPadding(tabIndex);

        List<JButton> buttons = new ArrayList<>();
        buttons.add(getAddButton());
        buttons.add(getModifyButton());
        buttons.add(getRemoveButton());

        this.addTagRuleTab(++tabIndex, allthresholds, allstrengths);

        this.addTableField(++tabIndex, getRulesTable(), buttons);
    }

    @Override
    public JButton[] getExtraButtons() {
        return new JButton[] {getPreviewRulesButton()};
    }

    @Override
    public String validateFields() {
        if (this.getStringValue(POLICY_NAME_PARAM).trim().isEmpty()) {
            return Constant.messages.getString("automation.dialog.ascanpolicy.error.badname");
        }
        return null;
    }

    @Override
    public void save() {
        this.job.getData().setName(this.getStringValue(JOB_NAME_PARAM));
        this.job.getData().getParameters().setName(this.getStringValue(POLICY_NAME_PARAM));

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

        this.job.getData().getPolicyDefinition().setRules(this.getRulesModel().getRules());
        this.job.getData().getPolicyDefinition().setAlertTagRule(createAlertTagRuleConfig());
        this.job.resetAndSetChanged();
    }

    @Override
    protected List<Rule> getRules() {
        return job.getData().getPolicyDefinition().getRules();
    }

    @Override
    protected PolicyDefinition.AlertTagRuleConfig getAlertTagRule() {
        return job.getData().getPolicyDefinition().getAlertTagRule();
    }
}
