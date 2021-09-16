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
package org.zaproxy.addon.automation.tests;

import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import java.util.stream.Collectors;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.automation.JobResultData;
import org.zaproxy.addon.automation.gui.AlertTestDialog;
import org.zaproxy.addon.automation.jobs.ActiveScanJob;
import org.zaproxy.addon.automation.jobs.ActiveScanJobResultData;
import org.zaproxy.addon.automation.jobs.JobUtils;
import org.zaproxy.addon.automation.jobs.PassiveScanJobResultData;
import org.zaproxy.addon.automation.jobs.PassiveScanWaitJob;
import org.zaproxy.zap.extension.alert.ExtensionAlert;

public class AutomationAlertTest extends AbstractAutomationTest {

    public static final String ACTION_PASS_IF_ABSENT = "passIfAbsent";
    public static final String ACTION_PASS_IF_PRESENT = "passIfPresent";

    static final String PARAM_SCAN_RULE_ID = "scanRuleId";
    static final String PARAM_ON_FAIL = "onFail";
    static final String PARAM_ACTION = "action";
    static final String PARAM_NAME = "name";
    static final String PARAM_ALERT_NAME = "alertName";
    static final String PARAM_URL = "url";
    static final String PARAM_METHOD = "method";
    static final String PARAM_ATTACK = "attack";
    static final String PARAM_PARAM = "param";
    static final String PARAM_EVIDENCE = "evidence";
    static final String PARAM_CONFIDENCE = "confidence";
    static final String PARAM_RISK = "risk";
    static final String PARAM_OTHER_INFO = "otherInfo";

    public static final String TEST_TYPE = "alert";

    private Data data;

    public AutomationAlertTest(String name, String onFail, AutomationJob job) {
        super(name, onFail, job);
        data = new Data(this);
    }

    public AutomationAlertTest(Map<?, ?> testData, AutomationJob job, AutomationProgress progress) {

        super(testData, job);
        data = new Data(this);
        if (Control.getSingleton().getExtensionLoader().getExtension(ExtensionAlert.class)
                == null) {
            progress.error(
                    Constant.messages.getString(
                            "automation.tests.alert.nullExtension", job.getType()));
        }
        if (!(job.getType().equals(ActiveScanJob.JOB_NAME)
                || job.getType().equals(PassiveScanWaitJob.JOB_NAME))) {
            progress.error(
                    Constant.messages.getString(
                            "automation.tests.alert.invalidJobType", job.getType()));
        }
        JobUtils.applyParamsToObject(testData, this.getData(), this.getName(), null, progress);

        if (this.getData().getOnFail() == null) {
            progress.error(
                    Constant.messages.getString(
                            "automation.tests.error.badonfail", getJobType(), this.getName()));
        }

        if (data.getScanRuleId() <= 0) {
            progress.error(
                    Constant.messages.getString(
                            "automation.tests.alert.error.noscanruleid",
                            getJobType(),
                            this.getName()));
        }

        if (isNullOrEmpty(this.getData().getAction())) {
            this.getData().setAction(ACTION_PASS_IF_ABSENT);
        }
        if (!(this.getData().getAction().equals(ACTION_PASS_IF_PRESENT)
                || this.getData().getAction().equals(ACTION_PASS_IF_ABSENT))) {
            progress.error(
                    Constant.messages.getString(
                            "automation.tests.alert.error.badaction",
                            getJobType(),
                            this.getName(),
                            this.getData().getAction()));
            this.getData().setAction(ACTION_PASS_IF_ABSENT);
        }

        JobUtils.parseAlertConfidence(this.getData().getConfidence(), this.getName(), progress);
        JobUtils.parseAlertRisk(this.getData().getRisk(), this.getName(), progress);

        if (isNullOrEmpty(this.getData().getName())) {
            this.getData()
                    .setName(this.getData().getScanRuleId() + ' ' + this.getData().getAction());
        }

        compilePattern(this.getData().getAlertName(), progress);
        compilePattern(this.getData().getUrl(), progress);
        compilePattern(this.getData().getMethod(), progress);
        compilePattern(this.getData().getAttack(), progress);
        compilePattern(this.getData().getParam(), progress);
        compilePattern(this.getData().getEvidence(), progress);
        compilePattern(this.getData().getConfidence(), progress);
        compilePattern(this.getData().getRisk(), progress);
        compilePattern(this.getData().getOtherInfo(), progress);
    }

    public AutomationAlertTest(AutomationJob job, AutomationProgress progress)
            throws IllegalArgumentException {
        super("", AbstractAutomationTest.OnFail.INFO.name(), job);
        data = new Data(this);
        data.setOnFail(AbstractAutomationTest.OnFail.INFO);
    }

    private Pattern compilePattern(String val, AutomationProgress progress) {
        if (!isNullOrEmpty(val)) {
            try {
                return Pattern.compile(val);
            } catch (PatternSyntaxException e) {
                progress.warn(
                        Constant.messages.getString(
                                "automation.tests.alert.badregex",
                                getJobType(),
                                val,
                                getName(),
                                e.getMessage()));
            }
        }
        return null;
    }

    private static boolean isNullOrEmpty(String val) {
        return val == null || val.isEmpty();
    }

    @Override
    public String getTestType() {
        return TEST_TYPE;
    }

    @Override
    public boolean runTest(AutomationProgress progress) {
        boolean passIfAbsent = this.getData().getAction().equals(ACTION_PASS_IF_ABSENT);
        String key =
                (getJobType().equals(ActiveScanJob.JOB_NAME))
                        ? ActiveScanJobResultData.KEY
                        : PassiveScanJobResultData.KEY;
        JobResultData resultData = progress.getJobResultData(key);
        List<Alert> alerts =
                resultData.getAllAlertData().stream()
                        .filter(t -> (t.getPluginId() == this.getData().getScanRuleId()))
                        .collect(Collectors.toList());

        if (alerts.isEmpty()) {
            return passIfAbsent;
        }

        Pattern alertNamePattern = compilePattern(this.getData().getAlertName(), progress);
        Pattern urlPattern = compilePattern(this.getData().getUrl(), progress);
        Pattern methodPattern = compilePattern(this.getData().getMethod(), progress);
        Pattern attackPattern = compilePattern(this.getData().getAttack(), progress);
        Pattern paramPattern = compilePattern(this.getData().getParam(), progress);
        Pattern evidencePattern = compilePattern(this.getData().getEvidence(), progress);
        Pattern otherInfoPattern = compilePattern(this.getData().getOtherInfo(), progress);
        Integer confidence =
                JobUtils.parseAlertConfidence(
                        this.getData().getConfidence(), this.getName(), progress);
        Integer risk = JobUtils.parseAlertRisk(this.getData().getRisk(), this.getName(), progress);

        for (Alert alert : alerts) {

            if (matches(alertNamePattern, alert.getName(), passIfAbsent)) {
                return false;
            }

            if (matches(urlPattern, alert.getUri(), passIfAbsent)) {
                return false;
            }

            if (matches(methodPattern, alert.getMethod(), passIfAbsent)) {
                return false;
            }

            if (matches(attackPattern, alert.getAttack(), passIfAbsent)) {
                return false;
            }

            if (matches(paramPattern, alert.getParam(), passIfAbsent)) {
                return false;
            }

            if (matches(evidencePattern, alert.getEvidence(), passIfAbsent)) {
                return false;
            }

            if (matchesInt(confidence, alert.getConfidence(), passIfAbsent)) {
                return false;
            }

            if (matchesInt(risk, alert.getRisk(), passIfAbsent)) {
                return false;
            }

            if (matches(otherInfoPattern, alert.getOtherInfo(), passIfAbsent)) {
                return false;
            }
        }

        return true;
    }

    private static boolean matches(Pattern pattern, String value, boolean passIfAbsent) {
        return pattern != null && pattern.matcher(value).matches() == passIfAbsent;
    }

    private static boolean matchesInt(Integer setValue, Integer value, boolean passIfAbsent) {
        return setValue != null && setValue.equals(value) == passIfAbsent;
    }

    @Override
    public String getTestPassedMessage() {
        String reason =
                this.getData().getAction().equals(ACTION_PASS_IF_ABSENT) ? "absent" : "present";
        String testPassedReason =
                Constant.messages.getString(
                        "automation.tests.alert.reason", this.getData().getScanRuleId(), reason);
        return Constant.messages.getString(
                "automation.tests.pass",
                getJobType(),
                getTestType(),
                this.getData().getName(),
                testPassedReason);
    }

    @Override
    public String getTestFailedMessage() {
        String reason =
                this.getData().getAction().equals(ACTION_PASS_IF_ABSENT) ? "present" : "absent";
        String testFailedReason =
                Constant.messages.getString(
                        "automation.tests.alert.reason", this.getData().getScanRuleId(), reason);
        return Constant.messages.getString(
                "automation.tests.fail",
                getJobType(),
                getTestType(),
                this.getData().getName(),
                testFailedReason);
    }

    @Override
    public void showDialog() {
        new AlertTestDialog(this).setVisible(true);
    }

    @Override
    public Data getData() {
        return data;
    }

    public static class Data extends TestData {

        private int scanRuleId;
        private String action;
        private String alertName;
        private String url;
        private String method;
        private String attack;
        private String param;
        private String evidence;
        private String confidence;
        private String risk;
        private String otherInfo;

        public Data(AutomationAlertTest test) {
            super(test);
        }

        public int getScanRuleId() {
            return scanRuleId;
        }

        public void setScanRuleId(int scanRuleId) {
            this.scanRuleId = scanRuleId;
        }

        public String getAction() {
            return action;
        }

        public void setAction(String action) {
            this.action = action;
        }

        public String getAlertName() {
            return alertName;
        }

        public void setAlertName(String alertName) {
            this.alertName = alertName;
        }

        public String getUrl() {
            return url;
        }

        public void setUrl(String url) {
            this.url = url;
        }

        public String getMethod() {
            return method;
        }

        public void setMethod(String method) {
            this.method = method;
        }

        public String getAttack() {
            return attack;
        }

        public void setAttack(String attack) {
            this.attack = attack;
        }

        public String getParam() {
            return param;
        }

        public void setParam(String param) {
            this.param = param;
        }

        public String getEvidence() {
            return evidence;
        }

        public void setEvidence(String evidence) {
            this.evidence = evidence;
        }

        public String getConfidence() {
            return confidence;
        }

        public void setConfidence(String confidence) {
            this.confidence = confidence;
        }

        public String getRisk() {
            return risk;
        }

        public void setRisk(String risk) {
            this.risk = risk;
        }

        public String getOtherInfo() {
            return otherInfo;
        }

        public void setOtherInfo(String otherInfo) {
            this.otherInfo = otherInfo;
        }
    }
}
