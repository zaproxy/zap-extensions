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
package org.zaproxy.addon.retest;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.automation.AutomationData;

public class AlertData extends AutomationData {
    private Integer scanRuleId;
    private String alertName;
    private String url;
    private String method;
    private String attack;
    private String param;
    private String evidence;
    private String confidence;
    private String risk;
    private String otherInfo;
    private Status status;
    private HttpMessage msg;
    private Alert alert;

    public enum Status {
        NOT_VERIFIED,
        PRESENT,
        ABSENT;

        @Override
        public String toString() {
            switch (this) {
                case NOT_VERIFIED:
                    return Constant.messages.getString("retest.dialog.table.status.notverified");
                case PRESENT:
                    return Constant.messages.getString("retest.dialog.table.status.present");
                case ABSENT:
                    return Constant.messages.getString("retest.dialog.table.status.absent");
                default:
                    return "";
            }
        }

        public static Status i18nToStatus(String str) {
            for (Status s : Status.values()) {
                if (s.toString().equals(str)) {
                    return s;
                }
            }
            return null;
        }
    }

    public AlertData() {}

    public AlertData(Alert alert, Status status) {
        this.scanRuleId = alert.getPluginId();
        this.alertName = alert.getName();
        this.url = alert.getUri();
        this.method = alert.getMethod();
        this.attack = alert.getAttack();
        this.param = alert.getParam();
        this.evidence = alert.getEvidence();
        this.confidence = Alert.MSG_CONFIDENCE[alert.getConfidence()];
        this.risk = Alert.MSG_RISK[alert.getRisk()];
        this.otherInfo = alert.getOtherInfo();
        this.status = status;
        this.msg = alert.getMessage();
        this.alert = alert;
    }

    public String getStatus() {
        return this.status.toString();
    }

    public void setStatus(Status status) {
        this.status = status;
    }

    public int getScanRuleId() {
        return scanRuleId;
    }

    public void setScanRuleId(int scanRuleId) {
        this.scanRuleId = scanRuleId;
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

    public HttpMessage getMsg() {
        return msg;
    }

    public void setMsg(HttpMessage msg) {
        this.msg = msg;
    }

    public Alert getAlert() {
        return alert;
    }

    public void setAlert(Alert alert) {
        this.alert = alert;
    }
}
