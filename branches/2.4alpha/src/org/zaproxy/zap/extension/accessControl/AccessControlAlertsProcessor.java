/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 * 
 * Copyright 2014 The ZAP Development Team.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); 
 * you may not use this file except in compliance with the License. 
 * You may obtain a copy of the License at 
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0 
 *   
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS, 
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
 * See the License for the specific language governing permissions and 
 * limitations under the License. 
 */
package org.zaproxy.zap.extension.accessControl;

import java.sql.SQLException;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.accessControl.AccessControlScannerThread.AccessControlResultEntry;
import org.zaproxy.zap.extension.accessControl.AccessControlScannerThread.AccessControlNodeResult;
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
	private static final Logger log = Logger.getLogger(AccessControlAlertsProcessor.class);

	private static Vulnerability vulnerabilityAuthentication = Vulnerabilities.getVulnerability("wasc_1");
	private static Vulnerability vulnerabilityAuthorization = Vulnerabilities.getVulnerability("wasc_2");

	private static final String AUTHENTICATION_ALERT_TITLE = Constant.messages
			.getString("accessControl.alert.authentication.name");
	private static final String AUTHORIZATION_ALERT_TITLE = Constant.messages
			.getString("accessControl.alert.authorization.name");

	private ExtensionAlert alertExtension;
	private boolean shouldRun;
	private int alertRiskLevel;

	public AccessControlAlertsProcessor(AccessControlScanStartOptions scanOptions) {
		this.alertExtension = (ExtensionAlert) Control.getSingleton().getExtensionLoader()
				.getExtension(ExtensionAlert.NAME);
		this.shouldRun = alertExtension != null && scanOptions.raiseAlerts;
		this.alertRiskLevel = scanOptions.alertRiskLevel;
	}

	public void processScanResult(AccessControlResultEntry result) {
		if (!shouldRun || result.getResult() != AccessControlNodeResult.ILLEGAL) {
			return;
		}

		if (log.isDebugEnabled()) {
			log.debug("Raising alert for: " + result);
		}

		if (result.getUser() == null) {
			raiseAuthenticationAlert(result);
		} else {
			raiseAuthorizationAlert(result);
		}

	}

	private void raiseAuthorizationAlert(AccessControlResultEntry result) {
		Alert alert = new Alert(10102, alertRiskLevel, Alert.HIGH, AUTHORIZATION_ALERT_TITLE);

		HttpMessage msg = null;
		try {
			msg = result.getHistoryReference().getHttpMessage();
		} catch (HttpMalformedHeaderException | SQLException e) {
			e.printStackTrace();
		}
		// @formatter:off
		alert.setDetail(Vulnerabilities.getDescription(vulnerabilityAuthorization), result.getUri(), "", // Param
				Constant.messages.getString("accessControl.alert.authorization.attack", result.getUser()
						.getName()), // Attack
				"", // Other info
				Vulnerabilities.getSolution(vulnerabilityAuthorization), // Solution
				Vulnerabilities.getReference(vulnerabilityAuthorization), // Reference
				Constant.messages.getString("accessControl.alert.authorization.evidence",
						result.isRequestAuthorized(), result.getAccessRule()), // Evidence
				285, // CWE Id
				2, // WASC Id
				msg);
		// @formatter:on

		alertExtension.alertFound(alert, result.getHistoryReference());
	}

	private void raiseAuthenticationAlert(AccessControlResultEntry result) {
		Alert alert = new Alert(10101, alertRiskLevel, Alert.HIGH, AUTHENTICATION_ALERT_TITLE);

		HttpMessage msg = null;
		try {
			msg = result.getHistoryReference().getHttpMessage();
		} catch (HttpMalformedHeaderException | SQLException e) {
			e.printStackTrace();
		}
		// @formatter:off
		alert.setDetail(Vulnerabilities.getDescription(vulnerabilityAuthentication), result.getUri(),
				"", // Param
				Constant.messages.getString("accessControl.alert.authentication.attack"), // Attack
				"", // Other info
				Vulnerabilities.getSolution(vulnerabilityAuthentication), // Solution
				Vulnerabilities.getReference(vulnerabilityAuthentication), // Reference
				Constant.messages.getString("accessControl.alert.authentication.evidence",
						result.isRequestAuthorized(), result.getAccessRule()), // Evidence
				287, // CWE Id
				1, // WASC Id
				msg);
		// @formatter:on

		alertExtension.alertFound(alert, result.getHistoryReference());

	}
}
