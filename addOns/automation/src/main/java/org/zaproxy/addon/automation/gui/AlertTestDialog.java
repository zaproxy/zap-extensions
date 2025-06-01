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

import java.util.Arrays;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.automation.jobs.JobUtils;
import org.zaproxy.addon.automation.tests.AbstractAutomationTest.OnFail;
import org.zaproxy.addon.automation.tests.AutomationAlertTest;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.StandardFieldsDialog;

@SuppressWarnings("serial")
public class AlertTestDialog extends StandardFieldsDialog {

    private static final long serialVersionUID = 1L;

    private static final String TITLE = "automation.dialog.alerttest.title";
    private static final String NAME_PARAM = "automation.dialog.all.name";
    private static final String ACTION_PARAM = "automation.dialog.alerttest.action";
    private static final String SCAN_RULE_ID_PARAM = "automation.dialog.alerttest.ruleid";
    private static final String ALERT_NAME_PARAM = "automation.dialog.alerttest.alertname";
    private static final String URL_PARAM = "automation.dialog.alerttest.url";
    private static final String METHOD_PARAM = "automation.dialog.alerttest.method";
    private static final String ATTACK_PARAM = "automation.dialog.alerttest.attack";
    private static final String PARAM_PARAM = "automation.dialog.alerttest.param";
    private static final String EVIDENCE_PARAM = "automation.dialog.alerttest.evidence";
    private static final String CONFIDENCE_PARAM = "automation.dialog.alerttest.confidence";
    private static final String RISK_PARAM = "automation.dialog.alerttest.risk";
    private static final String OTHER_PARAM = "automation.dialog.alerttest.other";
    private static final String ON_FAIL_PARAM = "automation.dialog.alerttest.onfail";

    private AutomationAlertTest test;

    public AlertTestDialog(AutomationAlertTest test) {
        super(View.getSingleton().getMainFrame(), TITLE, DisplayUtils.getScaledDimension(400, 500));
        this.test = test;

        this.addTextField(NAME_PARAM, test.getName());
        this.addComboField(
                ON_FAIL_PARAM,
                Arrays.asList(OnFail.values()).stream()
                        .map(OnFail::toString)
                        .toArray(String[]::new),
                test.getData().getOnFail().toString());
        this.addComboField(
                ACTION_PARAM,
                new String[] {
                    actionToi18n(AutomationAlertTest.ACTION_PASS_IF_ABSENT),
                    actionToi18n(AutomationAlertTest.ACTION_PASS_IF_PRESENT)
                },
                actionToi18n(test.getData().getAction()));
        this.addNumberField(
                SCAN_RULE_ID_PARAM, 0, Integer.MAX_VALUE, test.getData().getScanRuleId());

        String conf = "";
        Integer confInt = JobUtils.parseAlertConfidence(test.getData().getConfidence());
        if (confInt != null) {
            conf = Constant.messages.getString("automation.tests.alert.confidence." + confInt);
        }
        this.addComboField(
                CONFIDENCE_PARAM,
                new String[] {
                    "",
                    Constant.messages.getString("automation.tests.alert.confidence.0"),
                    Constant.messages.getString("automation.tests.alert.confidence.1"),
                    Constant.messages.getString("automation.tests.alert.confidence.2"),
                    Constant.messages.getString("automation.tests.alert.confidence.3"),
                },
                conf);

        String risk = "";
        Integer riskInt = JobUtils.parseAlertRisk(test.getData().getRisk());
        if (riskInt != null) {
            risk = Constant.messages.getString("automation.tests.alert.risk." + riskInt);
        }
        this.addComboField(
                RISK_PARAM,
                new String[] {
                    "",
                    Constant.messages.getString("automation.tests.alert.risk.0"),
                    Constant.messages.getString("automation.tests.alert.risk.1"),
                    Constant.messages.getString("automation.tests.alert.risk.2"),
                    Constant.messages.getString("automation.tests.alert.risk.3"),
                },
                risk);

        this.addTextField(ALERT_NAME_PARAM, test.getData().getAlertName());
        this.addTextField(URL_PARAM, test.getData().getUrl());
        this.addTextField(METHOD_PARAM, test.getData().getMethod());
        this.addTextField(ATTACK_PARAM, test.getData().getAttack());
        this.addTextField(PARAM_PARAM, test.getData().getParam());
        this.addTextField(EVIDENCE_PARAM, test.getData().getEvidence());
        this.addTextField(OTHER_PARAM, test.getData().getOtherInfo());
        this.addPadding();
    }

    private String actionToi18n(String action) {
        if (AutomationAlertTest.ACTION_PASS_IF_PRESENT.equals(action)) {
            return Constant.messages.getString("automation.tests.alert.action.passIfPresent");
        }
        return Constant.messages.getString("automation.tests.alert.action.passIfAbsent");
    }

    private String i18nToAction(String i18n) {
        if (i18n.equals(
                Constant.messages.getString("automation.tests.alert.action.passIfPresent"))) {
            return AutomationAlertTest.ACTION_PASS_IF_PRESENT;
        }
        return AutomationAlertTest.ACTION_PASS_IF_ABSENT;
    }

    private String emptyToNull(String str) {
        if (str != null && str.trim().isEmpty()) {
            return null;
        }
        return str;
    }

    @Override
    public void save() {
        this.test.getData().setName(this.getStringValue(NAME_PARAM));
        this.test.getData().setOnFail(OnFail.i18nToOnFail(this.getStringValue(ON_FAIL_PARAM)));
        this.test.getData().setAction(i18nToAction(this.getStringValue(ACTION_PARAM)));
        this.test.getData().setScanRuleId(this.getIntValue(SCAN_RULE_ID_PARAM));
        this.test.getData().setUrl(emptyToNull(this.getStringValue(URL_PARAM)));
        this.test.getData().setMethod(emptyToNull(this.getStringValue(METHOD_PARAM)));
        this.test.getData().setAttack(emptyToNull(this.getStringValue(ATTACK_PARAM)));
        this.test.getData().setParam(emptyToNull(this.getStringValue(PARAM_PARAM)));
        this.test.getData().setEvidence(emptyToNull(this.getStringValue(EVIDENCE_PARAM)));
        this.test.getData().setOtherInfo(emptyToNull(this.getStringValue(OTHER_PARAM)));

        String confI18n = this.getStringValue(CONFIDENCE_PARAM);
        String conf = null;
        for (int i = 0; i < Alert.MSG_CONFIDENCE.length; i++) {
            if (confI18n.equals(
                    Constant.messages.getString("automation.tests.alert.confidence." + i))) {
                conf = Alert.MSG_CONFIDENCE[i].toLowerCase();
                break;
            }
        }
        this.test.getData().setConfidence(conf);

        String riskI18n = this.getStringValue(RISK_PARAM);
        String risk = null;
        for (int i = 0; i < Alert.MSG_RISK.length; i++) {
            if (riskI18n.equals(Constant.messages.getString("automation.tests.alert.risk." + i))) {
                risk = Alert.MSG_RISK[i].toLowerCase();
                break;
            }
        }
        this.test.getData().setRisk(risk);
        this.test.getJob().getPlan().setChanged();
    }

    @Override
    public String validateFields() {
        // TODO check valid regexes
        return null;
    }
}
