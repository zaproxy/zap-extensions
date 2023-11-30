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
import net.sf.json.JSONObject;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.zaproxy.addon.client.ClientUtils;
import org.zaproxy.addon.client.ReportedElement;
import org.zaproxy.addon.client.ReportedObject;

public class InformationInStorageScanRule extends ClientPassiveAbstractScanRule {

    @Override
    public String getName() {
        return Constant.messages.getString("client.pscan.infoinstorage.stdname");
    }

    @Override
    public int getId() {
        return 120000;
    }

    @Override
    public void scanReportedObject(ReportedObject obj, ClientPassiveScanHelper helper) {
        if (ClientUtils.LOCAL_STORAGE.equals(obj.getType())
                || ClientUtils.SESSION_STORAGE.equals(obj.getType())) {
            helper.raiseAlert(
                    this.getAlertBuilder(obj).build(), helper.findHistoryRef(obj.getUrl()));
        }
    }

    private Alert.Builder getAlertBuilder(ReportedObject obj) {
        String value = obj.getText();
        String decodedValue = ClientPassiveScanHelper.base64Decode(value);

        return this.getBaseAlertBuilder(obj)
                .setAlertRef(
                        getId() + "-" + (ClientUtils.LOCAL_STORAGE.equals(obj.getType()) ? 1 : 2))
                .setName(
                        Constant.messages.getString(
                                "client.pscan.infoinstorage.name", obj.getType()))
                .setDescription(
                        Constant.messages.getString(
                                "client.pscan.infoinstorage.desc", obj.getType()))
                .setConfidence(Alert.CONFIDENCE_HIGH)
                .setRisk(Alert.RISK_INFO)
                .setOtherInfo(
                        decodedValue == null
                                ? Constant.messages.getString(
                                        "client.pscan.infoinstorage.other",
                                        obj.getId() + "=" + value)
                                : Constant.messages.getString(
                                        "client.pscan.infoinstorage.other.base64",
                                        obj.getId() + "=" + value,
                                        obj.getId() + "=" + decodedValue))
                .setSolution(Constant.messages.getString("client.pscan.infoinstorage.solution"))
                .setCweId(200) // CWE Id: 200 - Information Exposure
                .setWascId(13); // WASC Id: 13 - Information Leakage
    }

    @Override
    public List<Alert> getExampleAlerts() {
        List<Alert> alerts = new ArrayList<>();
        JSONObject obj = new JSONObject();
        obj.put("timestamp", 0L);
        obj.put("type", ClientUtils.LOCAL_STORAGE);
        obj.put("tagname", "");
        obj.put("id", "key");
        obj.put("text", "value");
        alerts.add(getAlertBuilder(new ReportedElement(obj)).build());
        obj.put("type", ClientUtils.SESSION_STORAGE);
        alerts.add(getAlertBuilder(new ReportedElement(obj)).build());
        return alerts;
    }
}
