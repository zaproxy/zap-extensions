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

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import net.sf.json.JSONObject;
import org.apache.commons.codec.binary.Hex;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.zaproxy.addon.client.ClientUtils;
import org.zaproxy.addon.client.ReportedElement;
import org.zaproxy.addon.client.ReportedObject;

public class JwtInStorageScanRule extends ClientPassiveAbstractScanRule {

    @Override
    public String getName() {
        return Constant.messages.getString("client.pscan.jwtinstorage.stdname");
    }

    @Override
    public int getId() {
        return 120002;
    }

    @Override
    public void scanReportedObject(ReportedObject obj, ClientPassiveScanHelper helper) {
        if (obj.getText() != null
                && (ClientUtils.LOCAL_STORAGE.equals(obj.getType())
                        || ClientUtils.SESSION_STORAGE.equals(obj.getType()))) {
            String[] values = obj.getText().split("\\.");
            // We expect JWTs to have 3 parts, but there could be just 2 if the None algorithm is
            // used
            if (values.length == 2 || values.length == 3) {
                String header = ClientPassiveScanHelper.base64Decode(values[0]);
                String payload = ClientPassiveScanHelper.base64Decode(values[1]);
                String sig = "";
                if (values.length == 3) {
                    sig = values[2];
                }

                if (header != null && payload != null) {
                    ObjectMapper om = new ObjectMapper();
                    try {
                        // Check both the header and payload are JSON
                        om.readTree(header);
                        om.readTree(payload);

                        helper.raiseAlert(
                                this.getAlertBuilder(obj, header, payload, sig).build(),
                                helper.findHistoryRef(obj.getUrl()));
                    } catch (Exception e) {
                        // One of the elements does not appear to be JSON, ignore
                    }
                }
            }
        }
    }

    private Alert.Builder getAlertBuilder(
            ReportedObject obj, String header, String payload, String sig) {
        boolean isLocal = ClientUtils.LOCAL_STORAGE.equals(obj.getType());
        String sigStr = sig;
        try {
            sigStr = Hex.encodeHexString(Base64.getUrlDecoder().decode(sig));
        } catch (Exception e) {
            // Not valid base64 (surprising) - leave as original
        }

        return this.getBaseAlertBuilder(obj)
                .setAlertRef(getId() + "-" + (isLocal ? 1 : 2))
                .setName(
                        Constant.messages.getString(
                                "client.pscan.jwtinstorage.name", obj.getType()))
                .setDescription(
                        Constant.messages.getString(
                                "client.pscan.jwtinstorage.desc."
                                        + (isLocal ? "local" : "session")))
                .setConfidence(Alert.CONFIDENCE_HIGH)
                .setRisk(isLocal ? Alert.RISK_MEDIUM : Alert.RISK_INFO)
                .setOtherInfo(
                        Constant.messages.getString(
                                "client.pscan.jwtinstorage.other",
                                obj.getId(),
                                header,
                                payload,
                                sigStr))
                .setSolution(
                        Constant.messages.getString(
                                "client.pscan.jwtinstorage.solution."
                                        + (isLocal ? "local" : "session")))
                .setReference("https://www.zaproxy.org/blog/2020-09-03-zap-jwt-scanner/")
                .setCweId(200) // CWE Id: 200 - Information Exposure
                .setWascId(13); // WASC Id: 13 - Information Leakage
    }

    @Override
    public List<Alert> getExampleAlerts() {
        String header = "{'alg': 'HS256', 'typ': 'JWT'}";
        String payload = "{'sub': '1234567890', 'name': 'John Doe', 'iat': 1516239022}";
        String sig = "012345678012345678012345678012345678012345678012345678012345678";
        List<Alert> alerts = new ArrayList<>();
        JSONObject obj = new JSONObject();
        obj.put("timestamp", 0L);
        obj.put("type", ClientUtils.LOCAL_STORAGE);
        obj.put("tagname", "");
        obj.put("id", "key");
        obj.put("text", "value");
        alerts.add(getAlertBuilder(new ReportedElement(obj), header, payload, sig).build());
        obj.put("type", ClientUtils.SESSION_STORAGE);
        alerts.add(getAlertBuilder(new ReportedElement(obj), header, payload, sig).build());
        return alerts;
    }
}
