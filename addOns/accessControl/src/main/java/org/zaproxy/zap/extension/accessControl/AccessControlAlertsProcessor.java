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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.accessControl.AccessControlScannerThread.AccessControlNodeResult;
import org.zaproxy.zap.extension.accessControl.AccessControlScannerThread.AccessControlResultEntry;
import org.zaproxy.zap.extension.accessControl.AccessControlScannerThread.AccessControlScanStartOptions;
import org.zaproxy.zap.extension.alert.ExtensionAlert;
import org.zaproxy.zap.model.Vulnerabilities;
import org.zaproxy.zap.model.Vulnerability;

/**
 * The object that processes obtained scan results and raises {@link Alert Alerts}, if necessary.
 *
 * @author cosminstefanxp
 */
public class AccessControlAlertsProcessor {
    private static final Logger log = LogManager.getLogger(AccessControlAlertsProcessor.class);

    private static Vulnerability vulnerabilityAuthentication =
            Vulnerabilities.getVulnerability("wasc_1");
    private static Vulnerability vulnerabilityAuthorization =
            Vulnerabilities.getVulnerability("wasc_2");

    private static final String AUTHENTICATION_ALERT_TITLE =
            Constant.messages.getString("accessControl.alert.authentication.name");
    private static final String AUTHORIZATION_ALERT_TITLE =
            Constant.messages.getString("accessControl.alert.authorization.name");

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

        log.debug("Raising alert for: {}", result);

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
            log.debug(e);
        }

        Alert alert =
                Alert.builder()
                        .setPluginId(10102)
                        .setRisk(alertRiskLevel)
                        .setConfidence(Alert.CONFIDENCE_HIGH)
                        .setName(AUTHORIZATION_ALERT_TITLE)
                        .setDescription(Vulnerabilities.getDescription(vulnerabilityAuthorization))
                        .setOtherInfo(
                                Constant.messages.getString(
                                        "accessControl.alert.authorization.otherinfo",
                                        result.getUser().getName(),
                                        result.isRequestAuthorized(),
                                        result.getAccessRule()))
                        .setSolution(Vulnerabilities.getSolution(vulnerabilityAuthorization))
                        .setReference(Vulnerabilities.getReference(vulnerabilityAuthorization))
                        .setCweId(205)
                        .setWascId(2)
                        .setMessage(msg)
                        .setUri(result.getUri())
                        .build();

        alertExtension.alertFound(alert, result.getHistoryReference());
    }

    private void raiseAuthenticationAlert(AccessControlResultEntry result) {
        HttpMessage msg = null;
        try {
            msg = result.getHistoryReference().getHttpMessage();
        } catch (HttpMalformedHeaderException | DatabaseException e) {
            log.debug(e);
        }

        Alert alert =
                Alert.builder()
                        .setPluginId(10101)
                        .setRisk(alertRiskLevel)
                        .setConfidence(Alert.CONFIDENCE_HIGH)
                        .setName(AUTHENTICATION_ALERT_TITLE)
                        .setDescription(Vulnerabilities.getDescription(vulnerabilityAuthentication))
                        .setOtherInfo(
                                Constant.messages.getString(
                                        "accessControl.alert.authentication.otherinfo",
                                        result.isRequestAuthorized(),
                                        result.getAccessRule()))
                        .setSolution(Vulnerabilities.getSolution(vulnerabilityAuthentication))
                        .setReference(Vulnerabilities.getReference(vulnerabilityAuthentication))
                        .setCweId(287)
                        .setWascId(1)
                        .setMessage(msg)
                        .setUri(result.getUri())
                        .build();

        alertExtension.alertFound(alert, result.getHistoryReference());
    }
}
