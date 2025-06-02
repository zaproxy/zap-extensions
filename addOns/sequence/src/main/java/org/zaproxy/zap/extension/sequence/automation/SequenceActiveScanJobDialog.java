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
package org.zaproxy.zap.extension.sequence.automation;

import java.util.ArrayList;
import java.util.List;
import javax.swing.JButton;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.zaproxy.addon.automation.gui.ActiveScanPolicyDialog;
import org.zaproxy.addon.automation.jobs.JobUtils;
import org.zaproxy.addon.automation.jobs.PolicyDefinition;
import org.zaproxy.addon.automation.jobs.PolicyDefinition.Rule;
import org.zaproxy.zap.utils.DisplayUtils;

@SuppressWarnings("serial")
public class SequenceActiveScanJobDialog extends ActiveScanPolicyDialog {

    private static final long serialVersionUID = 1L;

    private static final String[] TAB_LABELS = {
        "automation.dialog.tab.params",
        "automation.dialog.ascan.tab.policydefaults",
        "automation.dialog.ascan.tab.policyrules"
    };

    private static final String TITLE = "sequence.automation.ascan.dialog.title";
    private static final String JOB_NAME_PARAM = "sequence.automation.dialog.jobName";

    private static final String SEQUENCE_PARAM = "sequence.automation.ascan.dialog.sequence";
    private static final String CONTEXT_PARAM = "sequence.automation.ascan.dialog.context";
    private static final String USER_PARAM = "automation.dialog.all.user";
    private static final String POLICY_PARAM = "sequence.automation.ascan.dialog.policy";

    private SequenceActiveScanJob job;

    public SequenceActiveScanJobDialog(SequenceActiveScanJob job, List<String> sequences) {
        super(TITLE, DisplayUtils.getScaledDimension(500, 300), TAB_LABELS);
        this.job = job;

        addTextField(0, JOB_NAME_PARAM, job.getData().getName());

        addComboField(0, SEQUENCE_PARAM, sequences, job.getParameters().getSequence(), true);

        List<String> contextNames = job.getEnv().getContextNames();
        contextNames.add(0, "");
        addComboField(0, CONTEXT_PARAM, contextNames, job.getParameters().getContext());

        List<String> users = job.getEnv().getAllUserNames();
        users.add(0, "");
        addComboField(0, USER_PARAM, users, job.getData().getParameters().getUser());

        addTextField(0, POLICY_PARAM, job.getParameters().getPolicy());

        addPadding(0);

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

        addComboField(1, DEFAULT_THRESHOLD_PARAM, allthresholds, thresholdName);

        List<String> allstrengths = new ArrayList<>();

        for (AttackStrength at : AttackStrength.values()) {
            if (AttackStrength.DEFAULT.equals(at)) {
                continue;
            }
            allstrengths.add(JobUtils.strengthToI18n(at.name()));
        }

        addComboField(1, DEFAULT_STRENGTH_PARAM, allstrengths, strengthName);

        addPadding(1);

        List<JButton> buttons = new ArrayList<>();
        buttons.add(getAddButton());
        buttons.add(getModifyButton());
        buttons.add(getRemoveButton());

        addTableField(2, getRulesTable(), buttons);
    }

    @Override
    public void save() {
        job.getData().setName(getStringValue(JOB_NAME_PARAM));

        SequenceActiveScanJob.Parameters parameters = job.getParameters();
        parameters.setSequence(getStringValue(SEQUENCE_PARAM));
        parameters.setContext(getStringValue(CONTEXT_PARAM));
        parameters.setUser(getStringValue(USER_PARAM));
        parameters.setPolicy(getStringValue(POLICY_PARAM));

        PolicyDefinition policyDefinition = job.getData().getPolicyDefinition();

        policyDefinition.setDefaultStrength(
                JobUtils.i18nToStrength(getStringValue(DEFAULT_STRENGTH_PARAM)));
        policyDefinition.setDefaultThreshold(
                JobUtils.i18nToThreshold(getStringValue(DEFAULT_THRESHOLD_PARAM)));

        policyDefinition.setRules(getRulesModel().getRules());

        job.resetAndSetChanged();
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
