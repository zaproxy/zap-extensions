/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
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
package org.zaproxy.zap.extension.accessControl;

import java.util.List;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.vulnerabilities.Vulnerabilities;
import org.zaproxy.addon.commonlib.vulnerabilities.Vulnerability;
import org.zaproxy.zap.extension.accessControl.AccessControlScannerThread.AccessControlNodeResult;
import org.zaproxy.zap.extension.accessControl.AccessControlScannerThread.AccessControlResultEntry;
import org.zaproxy.zap.extension.accessControl.AccessControlScannerThread.AccessControlScanStartOptions;
import org.zaproxy.zap.extension.alert.ExtensionAlert;

/**
 * The object that processes obtained scan results and raises {@link Alert Alerts}, if necessary.
 *
 * @author cosminstefanxp
 */
public class AccessControlAlertsProcessor {
    private static final Logger LOGGER = LogManager.getLogger(AccessControlAlertsProcessor.class);

    private static final Vulnerability VULNERABILITY_AUTHENTICATION =
            Vulnerabilities.getDefault().get("wasc_1");
    private static final Vulnerability VULNERABILITY_AUTHORIZATION =
            Vulnerabilities.getDefault().get("wasc_2");

    private static final String AUTHENTICATION_ALERT_TITLE =
            Constant.messages.getString("accessControl.alert.authentication.name");
    private static final String AUTHORIZATION_ALERT_TITLE =
            Constant.messages.getString("accessControl.alert.authorization.name");

    private static final Map<String, String> ALERT_TAGS =
            CommonAlertTag.toMap(
                    CommonAlertTag.OWASP_2021_A01_BROKEN_AC,
                    CommonAlertTag.OWASP_2017_A05_BROKEN_AC);

    private ExtensionAlert alertExtension;
    private boolean shouldRun;
    private int alertRiskLevel;

    public AccessControlAlertsProcessor(AccessControlScanStartOptions scanOptions) {
        this.alertExtension =
                (ExtensionAlert)
                        Control.getSingleton()
                                .getExtensionLoader()
                                .getExtension(ExtensionAlert.NAME);
        this.shouldRun = alertExtension != null && scanOptions.isRaiseAlerts();
        this.alertRiskLevel = scanOptions.getAlertRiskLevel();
    }

    public void processScanResult(AccessControlResultEntry result) {
        if (!shouldRun || result.getResult() != AccessControlNodeResult.ILLEGAL) {
            return;
        }

        LOGGER.debug("Raising alert for: {}", result);

        if (result.getUser() == null) {
            raiseAuthenticationAlert(result);
        } else {
            raiseAuthorizationAlert(result);
        }
    }

    private void raiseAuthorizationAlert(AccessControlResultEntry result) {
        HttpMessage msg = null;
        try {
            msg = result.getHistoryReference().getHttpMessage();
        } catch (HttpMalformedHeaderException | DatabaseException e) {
            LOGGER.debug(e);
        }

        Alert alert =
                createAuthorizationAlert(
                                alertRiskLevel,
                                result.getUser().getName(),
                                result.isRequestAuthorized(),
                                result.getAccessRule(),
                                result.getUri())
                        .setMessage(msg)
                        .build();

        alertExtension.alertFound(alert, result.getHistoryReference());
    }

    private static Alert.Builder createAuthorizationAlert(
            int risk,
            String userName,
            boolean requestAuthorized,
            AccessRule accessRule,
            String uri) {
        return Alert.builder()
                .setPluginId(10102)
                .setRisk(risk)
                .setConfidence(Alert.CONFIDENCE_HIGH)
                .setName(AUTHORIZATION_ALERT_TITLE)
                .setDescription(VULNERABILITY_AUTHORIZATION.getDescription())
                .setOtherInfo(
                        Constant.messages.getString(
                                "accessControl.alert.authorization.otherinfo",
                                userName,
                                requestAuthorized,
                                accessRule))
                .setSolution(VULNERABILITY_AUTHORIZATION.getSolution())
                .setReference(VULNERABILITY_AUTHORIZATION.getReferencesAsString())
                .setCweId(205)
                .setWascId(2)
                .setUri(uri)
                .setTags(ALERT_TAGS);
    }

    private void raiseAuthenticationAlert(AccessControlResultEntry result) {
        HttpMessage msg = null;
        try {
            msg = result.getHistoryReference().getHttpMessage();
        } catch (HttpMalformedHeaderException | DatabaseException e) {
            LOGGER.debug(e);
        }

        Alert alert =
                createAuthenticationAlert(
                                alertRiskLevel,
                                result.isRequestAuthorized(),
                                result.getAccessRule(),
                                result.getUri())
                        .setMessage(msg)
                        .build();

        alertExtension.alertFound(alert, result.getHistoryReference());
    }

    private static Alert.Builder createAuthenticationAlert(
            int risk, boolean requestAuthorized, AccessRule accessRule, String uri) {
        return Alert.builder()
                .setPluginId(10101)
                .setRisk(risk)
                .setConfidence(Alert.CONFIDENCE_HIGH)
                .setName(AUTHENTICATION_ALERT_TITLE)
                .setDescription(VULNERABILITY_AUTHENTICATION.getDescription())
                .setOtherInfo(
                        Constant.messages.getString(
                                "accessControl.alert.authentication.otherinfo",
                                requestAuthorized,
                                accessRule))
                .setSolution(VULNERABILITY_AUTHENTICATION.getSolution())
                .setReference(VULNERABILITY_AUTHENTICATION.getReferencesAsString())
                .setCweId(287)
                .setWascId(1)
                .setUri(uri)
                .setTags(ALERT_TAGS);
    }

    static List<Alert> getExampleAlerts() {
        return List.of(
                createAuthenticationAlert(
                                Alert.RISK_HIGH,
                                true,
                                AccessRule.DENIED,
                                "http://example.com/auth/")
                        .build(),
                createAuthorizationAlert(
                                Alert.RISK_HIGH,
                                "username",
                                false,
                                AccessRule.ALLOWED,
                                "http://example.com/admin/")
                        .build());
    }
}
