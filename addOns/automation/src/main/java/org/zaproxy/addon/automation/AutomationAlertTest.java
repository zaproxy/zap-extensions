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
package org.zaproxy.addon.automation;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import java.util.stream.Collectors;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.zaproxy.addon.automation.jobs.ActiveScanJob;
import org.zaproxy.addon.automation.jobs.ActiveScanJobResultData;
import org.zaproxy.addon.automation.jobs.PassiveScanJobResultData;
import org.zaproxy.addon.automation.jobs.PassiveScanWaitJob;
import org.zaproxy.zap.extension.alert.ExtensionAlert;

public class AutomationAlertTest extends AbstractAutomationTest {

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

    public final Integer scanRuleId;
    public final String action;
    public final String name;
    public Pattern alertName;
    public Pattern url;
    public Pattern method;
    public Pattern attack;
    public Pattern param;
    public Pattern evidence;
    public Integer confidence;
    public Integer risk;
    public Pattern otherInfo;
    public final String onFail;

    public AutomationAlertTest(LinkedHashMap<?, ?> testData, String jobType) {
        super(testData, jobType);
        if (Control.getSingleton().getExtensionLoader().getExtension(ExtensionAlert.class)
                == null) {
            throw new IllegalArgumentException(
                    Constant.messages.getString("automation.tests.alert.nullExtension", jobType));
        }
        if (!(jobType.equals(ActiveScanJob.JOB_NAME)
                || jobType.equals(PassiveScanWaitJob.JOB_NAME))) {
            throw new IllegalArgumentException(
                    Constant.messages.getString("automation.tests.alert.invalidJobType", jobType));
        }
        Integer scanRuleId =
                AutomationJob.safeCast(testData.get(PARAM_SCAN_RULE_ID), Integer.class);
        String onFail = AutomationJob.safeCast(testData.get(PARAM_ON_FAIL), String.class);
        String action = AutomationJob.safeCast(testData.get(PARAM_ACTION), String.class);
        if (isNullOrEmpty(action)) {
            action = "passIfAbsent";
        }
        if (scanRuleId == null
                || onFail == null
                || !(action.equals("passIfPresent") || action.equals("passIfAbsent"))) {
            throw new IllegalArgumentException(
                    Constant.messages.getString(
                            "automation.tests.missingOrInvalidProperties", jobType, getTestType()));
        }
        String name = AutomationJob.safeCast(testData.get(PARAM_NAME), String.class);
        if (isNullOrEmpty(name)) {
            name = scanRuleId + ' ' + action;
        }

        this.scanRuleId = scanRuleId;
        this.action = action;
        this.name = name;

        String alertName = AutomationJob.safeCast(testData.get(PARAM_ALERT_NAME), String.class);
        String url = AutomationJob.safeCast(testData.get(PARAM_URL), String.class);
        String method = AutomationJob.safeCast(testData.get(PARAM_METHOD), String.class);
        String attack = AutomationJob.safeCast(testData.get(PARAM_ATTACK), String.class);
        String param = AutomationJob.safeCast(testData.get(PARAM_PARAM), String.class);
        String evidence = AutomationJob.safeCast(testData.get(PARAM_EVIDENCE), String.class);
        String confidence = AutomationJob.safeCast(testData.get(PARAM_CONFIDENCE), String.class);
        String risk = AutomationJob.safeCast(testData.get(PARAM_RISK), String.class);
        String otherInfo = AutomationJob.safeCast(testData.get(PARAM_OTHER_INFO), String.class);

        this.alertName = compilePattern(alertName);
        this.url = compilePattern(url);
        this.method = compilePattern(method);
        this.attack = compilePattern(attack);
        this.param = compilePattern(param);
        this.evidence = compilePattern(evidence);

        Pattern confPattern = compilePattern(confidence);
        if (confPattern != null) {
            int idx = findIndexInArray(confPattern, Alert.MSG_CONFIDENCE);
            if (idx == -1) {
                throw new IllegalArgumentException(
                        Constant.messages.getString(
                                "automation.tests.alert.invalidConfidence",
                                jobType,
                                name,
                                confidence));
            }
            this.confidence = idx;
        }
        Pattern riskPattern = compilePattern(risk);
        if (riskPattern != null) {
            int idx = findIndexInArray(riskPattern, Alert.MSG_RISK);
            if (idx == -1) {
                throw new IllegalArgumentException(
                        Constant.messages.getString(
                                "automation.tests.alert.invalidRisk", jobType, name, risk));
            }
            this.risk = idx;
        }

        this.otherInfo = compilePattern(otherInfo);
        this.onFail = onFail;
    }

    private Pattern compilePattern(String val) {
        if (!isNullOrEmpty(val)) {
            try {
                return Pattern.compile(val);
            } catch (PatternSyntaxException e) {
                throw new IllegalArgumentException(
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

    private static int findIndexInArray(Pattern pattern, String[] array) {
        for (int i = 0; i < array.length; i++) {
            if (pattern.matcher(array[i]).matches()) {
                return i;
            }
        }
        return -1;
    }

    @Override
    public String getName() {
        return this.name;
    }

    @Override
    public String getTestType() {
        return TEST_TYPE;
    }

    @Override
    public boolean runTest(AutomationProgress progress) {
        boolean passIfAbsent = this.action.equals("passIfAbsent");
        String key =
                (getJobType().equals(ActiveScanJob.JOB_NAME))
                        ? ActiveScanJobResultData.KEY
                        : PassiveScanJobResultData.KEY;
        JobResultData resultData = progress.getJobResultData(key);
        List<Alert> alerts =
                resultData.getAllAlertData().stream()
                        .filter(t -> (t.getPluginId() == this.scanRuleId))
                        .collect(Collectors.toList());

        if (alerts.size() == 0) {
            return passIfAbsent;
        }

        for (Alert alert : alerts) {

            if (matches(this.alertName, alert.getName(), passIfAbsent)) {
                return false;
            }

            if (matches(this.url, alert.getUri(), passIfAbsent)) {
                return false;
            }

            if (matches(this.method, alert.getMethod(), passIfAbsent)) {
                return false;
            }

            if (matches(this.attack, alert.getAttack(), passIfAbsent)) {
                return false;
            }

            if (matches(this.param, alert.getParam(), passIfAbsent)) {
                return false;
            }

            if (matches(this.evidence, alert.getEvidence(), passIfAbsent)) {
                return false;
            }

            if (matchesInt(this.confidence, alert.getConfidence(), passIfAbsent)) {
                return false;
            }

            if (matchesInt(this.risk, alert.getRisk(), passIfAbsent)) {
                return false;
            }

            if (matches(this.otherInfo, alert.getOtherInfo(), passIfAbsent)) {
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
        String reason = this.action.equals("passIfAbsent") ? "absent" : "present";
        String testPassedReason =
                Constant.messages.getString("automation.tests.alert.reason", scanRuleId, reason);
        return Constant.messages.getString(
                "automation.tests.pass", getJobType(), getTestType(), name, testPassedReason);
    }

    @Override
    public String getTestFailedMessage() {
        String reason = this.action.equals("passIfAbsent") ? "present" : "absent";
        String testFailedReason =
                Constant.messages.getString("automation.tests.alert.reason", scanRuleId, reason);
        return Constant.messages.getString(
                "automation.tests.fail", getJobType(), getTestType(), name, testFailedReason);
    }
}
