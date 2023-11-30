/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.zaproxy.addon.client.pscan;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.sf.json.JSONObject;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.model.HistoryReference;
import org.zaproxy.addon.client.ClientUtils;
import org.zaproxy.addon.client.ReportedElement;
import org.zaproxy.addon.client.ReportedObject;

public class SensitiveInfoInStorageScanRule extends ClientPassiveAbstractScanRule {

    private static final String LOCAL_STORAGE = "localStorage";
    private static final String SESSION_STORAGE = "sessionStorage";

    private enum InfoType {
        cc,
        email,
        ssn
    };

    // Patterns copied from {@link InformationDisclosureInUrlScanRule}
    static Pattern emailAddressPattern =
            Pattern.compile("\\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,4}\\b");
    // CC Pattern Source:
    // https://www.oreilly.com/library/view/regular-expressions-cookbook/9781449327453/ch04s20.html
    static Pattern creditCardPattern =
            Pattern.compile(
                    "\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\\d{3})\\d{11})\\b");
    static Pattern usSSNPattern = Pattern.compile("\\b[0-9]{3}-[0-9]{2}-[0-9]{4}\\b");

    @Override
    public String getName() {
        return Constant.messages.getString("client.pscan.seninfoinstorage.stdname");
    }

    @Override
    public int getId() {
        return 120001;
    }

    @Override
    public void scanReportedObject(ReportedObject obj, ClientPassiveScanHelper helper) {
        if (LOCAL_STORAGE.equals(obj.getType()) || SESSION_STORAGE.equals(obj.getType())) {
            HistoryReference hr = helper.findHistoryRef(obj.getUrl());
            String value = obj.getText();
            String decodedValue = ClientPassiveScanHelper.base64Decode(value);

            if (isCreditCard(value) || isCreditCard(decodedValue)) {
                helper.raiseAlert(this.getAlertBuilder(obj, decodedValue, InfoType.cc).build(), hr);
            }
            if (isEmailAddress(value) || isEmailAddress(decodedValue)) {
                helper.raiseAlert(
                        this.getAlertBuilder(obj, decodedValue, InfoType.email).build(), hr);
            }
            if (isUsSSN(value) || isUsSSN(decodedValue)) {
                helper.raiseAlert(
                        this.getAlertBuilder(obj, decodedValue, InfoType.ssn).build(), hr);
            }
        }
    }

    protected Alert.Builder getAlertBuilder(
            ReportedObject obj, String decodedValue, InfoType infoType) {
        return this.getBaseAlertBuilder(obj)
                .setAlertRef(
                        getId() + "-" + (ClientUtils.LOCAL_STORAGE.equals(obj.getType()) ? 1 : 2))
                .setName(
                        Constant.messages.getString(
                                "client.pscan.seninfoinstorage.name", obj.getType()))
                .setDescription(
                        Constant.messages.getString(
                                "client.pscan.seninfoinstorage.desc", obj.getType()))
                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                .setRisk(Alert.RISK_LOW)
                .setOtherInfo(
                        decodedValue == null
                                ? Constant.messages.getString(
                                        "client.pscan.seninfoinstorage.other." + infoType,
                                        obj.getId() + "=" + obj.getText())
                                : Constant.messages.getString(
                                        "client.pscan.seninfoinstorage.other.base64." + infoType,
                                        obj.getId() + "=" + obj.getText(),
                                        obj.getId() + "=" + decodedValue))
                .setSolution(Constant.messages.getString("client.pscan.seninfoinstorage.solution"))
                .setCweId(200) // CWE Id: 200 - Information Exposure
                .setWascId(13); // WASC Id: 13 - Information Leakage
    }

    @Override
    public List<Alert> getExampleAlerts() {
        List<Alert> alerts = new ArrayList<>();
        JSONObject obj = new JSONObject();
        obj.put("timestamp", 0L);
        obj.put("type", LOCAL_STORAGE);
        obj.put("tagname", "");
        obj.put("id", "key");
        obj.put("text", "value");
        alerts.add(getAlertBuilder(new ReportedElement(obj), null, InfoType.cc).build());
        obj.put("type", SESSION_STORAGE);
        alerts.add(getAlertBuilder(new ReportedElement(obj), null, InfoType.email).build());
        return alerts;
    }

    private boolean isEmailAddress(String value) {
        if (value == null) {
            return false;
        }
        Matcher matcher = emailAddressPattern.matcher(value);
        return matcher.find();
    }

    private boolean isCreditCard(String value) {
        if (value == null) {
            return false;
        }
        Matcher matcher = creditCardPattern.matcher(value);
        return matcher.find();
    }

    private boolean isUsSSN(String value) {
        if (value == null) {
            return false;
        }
        Matcher matcher = usSSNPattern.matcher(value);
        return matcher.find();
    }
}
