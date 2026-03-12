/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.zap.extension.httpsinfo;

import com.mps.deepviolet.api.DeepVioletException;
import com.mps.deepviolet.api.DeepVioletFactory;
import com.mps.deepviolet.api.ICipherSuite;
import com.mps.deepviolet.api.IEngine;
import com.mps.deepviolet.api.IRiskScore;
import com.mps.deepviolet.api.IRiskScore.ICategoryScore;
import com.mps.deepviolet.api.IRiskScore.IDeduction;
import com.mps.deepviolet.api.ISession;
import com.mps.deepviolet.api.IX509Certificate;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.HashMap;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.AbstractHostPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;

/**
 * Active scan rule that performs HTTPS configuration analysis per host. Skips HTTP sites and raises
 * an info-level alert with certificate and cipher suite details for HTTPS sites.
 */
public class HttpsConfigScanRule extends AbstractHostPlugin {

    private static final String MESSAGE_PREFIX = "httpsinfo.scan.";
    private static final int PLUGIN_ID = 10205;
    private static final Logger LOGGER = LogManager.getLogger(HttpsConfigScanRule.class);

    @Override
    public int getId() {
        return PLUGIN_ID;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(MESSAGE_PREFIX + "desc");
    }

    @Override
    public String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    @Override
    public String getReference() {
        return Constant.messages.getString(MESSAGE_PREFIX + "refs");
    }

    @Override
    public int getCategory() {
        return Category.INFO_GATHER;
    }

    @Override
    public int getRisk() {
        return Alert.RISK_INFO;
    }

    @Override
    public int getCweId() {
        return 311; // CWE-311: Missing Encryption of Sensitive Data
    }

    @Override
    public int getWascId() {
        return 4; // WASC-04: Insufficient Transport Layer Protection
    }

    private static final String ALERT_REF_INFO = PLUGIN_ID + "-1";
    private static final String ALERT_REF_FAILURE = PLUGIN_ID + "-2";

    @Override
    public List<Alert> getExampleAlerts() {
        String exampleUri = "https://example.com/";
        String exampleConfigReport =
                "Server: example.com\n"
                        + "Server Certificate(s):\n"
                        + "  Subject DN: CN=example.com\n"
                        + "  Signing Algorithm: SHA256withRSA\n"
                        + "  Certificate Fingerprint: AA:BB:CC:...\n"
                        + "Cipher Suites Supported:\n"
                        + "  TLS_AES_256_GCM_SHA384 (STRONG, TLSv1.3)\n"
                        + "  TLS_CHACHA20_POLY1305_SHA256 (STRONG, TLSv1.3)\n";

        String failureHighReport =
                Constant.messages.getString(MESSAGE_PREFIX + "failure.desc")
                        + "\n"
                        + Constant.messages.getString(MESSAGE_PREFIX + "failure.score", "45")
                        + "\n"
                        + Constant.messages.getString(MESSAGE_PREFIX + "failure.grade", "F")
                        + "\n\n"
                        + Constant.messages.getString(MESSAGE_PREFIX + "failure.findings")
                        + "\n"
                        + "Certificate & Chain: Certificate expired\n"
                        + "  - [SYS-0020100] Certificate expired (CRITICAL)\n\n"
                        + Constant.messages.getString(MESSAGE_PREFIX + "failure.config")
                        + "\n"
                        + "Server: example.com\n"
                        + "Server Certificate(s):\n"
                        + "  Subject DN: CN=example.com\n"
                        + "Cipher Suites Supported:\n"
                        + "  TLS_AES_256_GCM_SHA384 (STRONG, TLSv1.3)\n";

        return List.of(
                newAlert()
                        .setAlertRef(ALERT_REF_INFO)
                        .setRisk(Alert.RISK_INFO)
                        .setConfidence(Alert.CONFIDENCE_HIGH)
                        .setUri(exampleUri)
                        .setOtherInfo(exampleConfigReport)
                        .build(),
                newAlert()
                        .setAlertRef(ALERT_REF_FAILURE)
                        .setRisk(Alert.RISK_HIGH)
                        .setConfidence(Alert.CONFIDENCE_HIGH)
                        .setName(Constant.messages.getString(MESSAGE_PREFIX + "failure.name"))
                        .setDescription(
                                Constant.messages.getString(MESSAGE_PREFIX + "failure.desc"))
                        .setSolution(Constant.messages.getString(MESSAGE_PREFIX + "failure.soln"))
                        .setReference(Constant.messages.getString(MESSAGE_PREFIX + "failure.refs"))
                        .setUri(exampleUri)
                        .setOtherInfo(failureHighReport)
                        .build());
    }

    @Override
    public void scan() {
        HttpMessage baseMsg = getBaseMsg();
        if (!baseMsg.getRequestHeader().isSecure()) {
            LOGGER.debug(
                    "Skipping HTTPS config scan for HTTP site: {}",
                    baseMsg.getRequestHeader().getURI());
            return;
        }

        URL target;
        try {
            target = URI.create(baseMsg.getRequestHeader().getURI().toString()).toURL();
        } catch (MalformedURLException e) {
            LOGGER.warn(
                    "Invalid target URL for HTTPS scan: {}",
                    baseMsg.getRequestHeader().getURI(),
                    e);
            return;
        }

        if (isStop()) {
            return;
        }

        try {
            ISession session = DeepVioletFactory.initializeSession(target);
            if (isStop()) {
                return;
            }

            IEngine engine = DeepVioletFactory.getEngine(session);
            if (isStop()) {
                return;
            }

            StringBuilder report = new StringBuilder();
            ExtensionHttpsInfo extHttpsInfo =
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionHttpsInfo.class);
            String proxyChainWarning =
                    extHttpsInfo != null ? extHttpsInfo.getProxyChainWarning() : null;
            if (proxyChainWarning != null) {
                report.append(proxyChainWarning)
                        .append(System.lineSeparator())
                        .append(System.lineSeparator());
            }
            report.append(
                    Constant.messages.getString(
                            "httpsinfo.general.server.leadin", target.getHost()));
            report.append(System.lineSeparator());

            if (engine.getCertificate() != null) {
                report.append(Constant.messages.getString("httpsinfo.general.cert.heading"));
                report.append("  ");
                report.append(buildCertDetails(engine.getCertificate()));
                report.append(System.lineSeparator());
            } else {
                report.append(Constant.messages.getString("httpsinfo.general.cert.notfound"));
            }

            ICipherSuite[] ciphers = engine.getCipherSuites();
            if (ciphers != null && ciphers.length > 0) {
                report.append(
                        Constant.messages.getString("httpsinfo.ciphersuites.supported.label"));
                report.append(System.lineSeparator());
                HashMap<ICipherSuite, ICipherSuite> csMap = new HashMap<>();
                for (ICipherSuite cipher : ciphers) {
                    if (!csMap.containsKey(cipher)) {
                        report.append(cipher.getSuiteName());
                        report.append('(');
                        report.append(cipher.getStrengthEvaluation());
                        report.append(',');
                        report.append(cipher.getHandshakeProtocol());
                        report.append(')');
                        report.append(System.lineSeparator());
                        csMap.put(cipher, cipher);
                    }
                }
            }

            newAlert()
                    .setAlertRef(ALERT_REF_INFO)
                    .setConfidence(Alert.CONFIDENCE_HIGH)
                    .setMessage(baseMsg)
                    .setOtherInfo(report.toString())
                    .raise();

            if (isStop()) {
                return;
            }

            raiseSecurityFailureAlertsIfNeeded(engine, baseMsg, report.toString());

        } catch (DeepVioletException e) {
            LOGGER.warn("HTTPS configuration scan failed for {}: {}", target, e.getMessage(), e);
        }
    }

    private void raiseSecurityFailureAlertsIfNeeded(
            IEngine engine, HttpMessage baseMsg, String configReport) {
        try {
            IRiskScore riskScore = engine.getRiskScore();
            if (riskScore == null) {
                return;
            }

            StringBuilder failureDetails = new StringBuilder();
            int worstRiskLevel = Alert.RISK_INFO;

            for (ICategoryScore category : riskScore.getCategoryScores()) {
                if (category == null) {
                    continue;
                }
                IDeduction[] deductions = category.getDeductions();
                if (deductions == null || deductions.length == 0) {
                    continue;
                }

                failureDetails.append(System.lineSeparator());
                failureDetails.append(category.getDisplayName());
                failureDetails.append(": ");
                failureDetails.append(category.getSummary());
                failureDetails.append(System.lineSeparator());

                for (IDeduction deduction : deductions) {
                    int zapRisk = mapSeverityToZapRisk(deduction.getSeverity());
                    if (zapRisk > worstRiskLevel) {
                        worstRiskLevel = zapRisk;
                    }
                    failureDetails.append("  - [");
                    failureDetails.append(deduction.getRuleId());
                    failureDetails.append("] ");
                    failureDetails.append(deduction.getDescription());
                    failureDetails.append(" (");
                    failureDetails.append(deduction.getSeverity());
                    failureDetails.append(")");
                    failureDetails.append(System.lineSeparator());
                }
            }

            if (failureDetails.length() == 0) {
                return;
            }

            if (worstRiskLevel <= Alert.RISK_INFO) {
                worstRiskLevel = Alert.RISK_LOW;
            }

            StringBuilder fullReport = new StringBuilder();
            fullReport.append(Constant.messages.getString(MESSAGE_PREFIX + "failure.desc"));
            fullReport.append(System.lineSeparator());
            fullReport.append(
                    Constant.messages.getString(
                            MESSAGE_PREFIX + "failure.score", riskScore.getTotalScore()));
            fullReport.append(System.lineSeparator());
            IRiskScore.LetterGrade grade = riskScore.getLetterGrade();
            fullReport.append(
                    Constant.messages.getString(
                            MESSAGE_PREFIX + "failure.grade",
                            grade != null ? grade.toDisplayString() : "N/A"));
            fullReport.append(System.lineSeparator());
            fullReport.append(System.lineSeparator());
            fullReport.append(Constant.messages.getString(MESSAGE_PREFIX + "failure.findings"));
            fullReport.append(failureDetails);
            fullReport.append(System.lineSeparator());
            fullReport.append(Constant.messages.getString(MESSAGE_PREFIX + "failure.config"));
            fullReport.append(System.lineSeparator());
            fullReport.append(configReport);

            newAlert()
                    .setAlertRef(ALERT_REF_FAILURE)
                    .setRisk(worstRiskLevel)
                    .setConfidence(Alert.CONFIDENCE_HIGH)
                    .setName(Constant.messages.getString(MESSAGE_PREFIX + "failure.name"))
                    .setDescription(Constant.messages.getString(MESSAGE_PREFIX + "failure.desc"))
                    .setSolution(Constant.messages.getString(MESSAGE_PREFIX + "failure.soln"))
                    .setReference(Constant.messages.getString(MESSAGE_PREFIX + "failure.refs"))
                    .setMessage(baseMsg)
                    .setOtherInfo(fullReport.toString())
                    .raise();

        } catch (DeepVioletException e) {
            LOGGER.debug("Failed to compute risk score: {}", e.getMessage());
        }
    }

    private static int mapSeverityToZapRisk(String severity) {
        if (severity == null) {
            return Alert.RISK_LOW;
        }
        return switch (severity.toUpperCase()) {
            case "CRITICAL" -> Alert.RISK_HIGH;
            case "HIGH" -> Alert.RISK_HIGH;
            case "MEDIUM" -> Alert.RISK_MEDIUM;
            case "LOW" -> Alert.RISK_LOW;
            default -> Alert.RISK_LOW;
        };
    }

    private String buildCertDetails(IX509Certificate cert) {
        StringBuilder sb = new StringBuilder();
        String newline = System.lineSeparator();
        sb.append(Constant.messages.getString("httpsinfo.general.subject.dn"))
                .append(' ')
                .append(cert.getSubjectDN())
                .append(newline);
        sb.append(Constant.messages.getString("httpsinfo.general.signing.algo"))
                .append(' ')
                .append(cert.getSigningAlgorithm())
                .append(newline);
        sb.append(Constant.messages.getString("httpsinfo.general.cert.fingerprint"))
                .append(' ')
                .append(cert.getCertificateFingerPrint())
                .append(newline);
        sb.append(Constant.messages.getString("httpsinfo.general.issuer.dn"))
                .append(' ')
                .append(cert.getIssuerDN())
                .append(newline);
        sb.append(Constant.messages.getString("httpsinfo.general.not.valid.before"))
                .append(' ')
                .append(cert.getNotValidBefore())
                .append(newline);
        sb.append(Constant.messages.getString("httpsinfo.general.not.valid.after"))
                .append(' ')
                .append(cert.getNotValidAfter())
                .append(newline);
        sb.append(Constant.messages.getString("httpsinfo.general.cert.serial.number"))
                .append(' ')
                .append(cert.getCertificateSerialNumber().toString())
                .append(newline);
        sb.append(Constant.messages.getString("httpsinfo.general.cert.version"))
                .append(' ')
                .append(cert.getCertificateVersion())
                .append(newline);
        sb.append(Constant.messages.getString("httpsinfo.general.cert.self.signed"))
                .append(' ')
                .append(cert.isSelfSignedCertificate())
                .append(newline);
        return sb.toString();
    }
}
