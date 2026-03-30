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
import com.mps.deepviolet.api.IX509Certificate;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.AbstractHostPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;

/**
 * Active scan rule that performs HTTPS configuration analysis per host. Skips HTTP sites and raises
 * an info-level alert with certificate and cipher suite details for HTTPS sites.
 */
public class HttpsConfigScanRule extends AbstractHostPlugin {

    private static final String MESSAGE_PREFIX = "httpsinfo.scan.";
    private static final int PLUGIN_ID = 10205;
    private static final Logger LOGGER = LogManager.getLogger(HttpsConfigScanRule.class);

    private static final String ALERT_REF_INFO = PLUGIN_ID + "-1";
    private static final String ALERT_REF_FAILURE = PLUGIN_ID + "-2";

    private static final Map<String, String> ALERT_TAGS;

    static {
        Map<String, String> alertTags =
                new HashMap<>(
                        CommonAlertTag.toMap(
                                CommonAlertTag.OWASP_2025_A04_CRYPTO_FAIL,
                                CommonAlertTag.OWASP_2021_A02_CRYPO_FAIL,
                                CommonAlertTag.OWASP_2017_A03_DATA_EXPOSED,
                                CommonAlertTag.WSTG_V42_CRYP_01_TLS,
                                CommonAlertTag.SYSTEMIC));
        alertTags.put(PolicyTag.QA_STD.getTag(), "");
        alertTags.put(PolicyTag.QA_FULL.getTag(), "");
        alertTags.put(PolicyTag.API.getTag(), "");
        alertTags.put(PolicyTag.PENTEST.getTag(), "");
        alertTags.put(PolicyTag.SEQUENCE.getTag(), "");
        ALERT_TAGS = Collections.unmodifiableMap(alertTags);
    }

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
        return Category.SERVER;
    }

    @Override
    public int getRisk() {
        return Alert.RISK_HIGH;
    }

    @Override
    public int getCweId() {
        return 311; // CWE-311: Missing Encryption of Sensitive Data
    }

    @Override
    public int getWascId() {
        return 4; // WASC-04: Insufficient Transport Layer Protection
    }

    public String getHelpLink() {
        return "https://www.zaproxy.org/docs/desktop/addons/https-info/ascanrule/#id-" + getId();
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    @Override
    public List<Alert> getExampleAlerts() {
        String exampleUri = "https://example.com/";
        IX509Certificate exampleCert = new ExampleIX509Certificate();
        ICipherSuite[] exampleCiphers = {
            new ExampleICipherSuite("TLS_AES_256_GCM_SHA384", "STRONG", "TLSv1.3"),
            new ExampleICipherSuite("TLS_CHACHA20_POLY1305_SHA256", "STRONG", "TLSv1.3")
        };
        String exampleConfigReport =
                buildConfigReport("example.com", null, exampleCert, exampleCiphers);
        String exampleFailureDetails =
                "Certificate & Chain: Certificate expired\n"
                        + "  - [SYS-0020100] Certificate expired (CRITICAL)\n\n";
        String exampleFailureReport =
                buildFailureReport("45", "F", exampleFailureDetails, exampleConfigReport);
        return List.of(
                buildInfoAlert(null, exampleUri, exampleConfigReport).build(),
                buildFailureAlert(null, exampleUri, exampleFailureReport, Alert.RISK_HIGH).build());
    }

    private AlertBuilder buildInfoAlert(HttpMessage message, String uri, String configReport) {
        var builder =
                newAlert()
                        .setAlertRef(ALERT_REF_INFO)
                        .setRisk(Alert.RISK_INFO)
                        .setConfidence(Alert.CONFIDENCE_HIGH)
                        .setOtherInfo(configReport);
        if (message != null) {
            builder.setMessage(message);
        } else {
            builder.setUri(uri);
        }
        return builder;
    }

    private AlertBuilder buildFailureAlert(
            HttpMessage message, String uri, String failureReport, int riskLevel) {
        var builder =
                newAlert()
                        .setAlertRef(ALERT_REF_FAILURE)
                        .setRisk(riskLevel)
                        .setConfidence(Alert.CONFIDENCE_HIGH)
                        .setName(Constant.messages.getString(MESSAGE_PREFIX + "failure.name"))
                        .setDescription(
                                Constant.messages.getString(MESSAGE_PREFIX + "failure.desc"))
                        .setSolution(Constant.messages.getString(MESSAGE_PREFIX + "failure.soln"))
                        .setReference(Constant.messages.getString(MESSAGE_PREFIX + "failure.refs"))
                        .setOtherInfo(failureReport);
        if (message != null) {
            builder.setMessage(message);
        } else {
            builder.setUri(uri);
        }
        return builder;
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
            IEngine engine =
                    DeepVioletFactory.getEngine(DeepVioletFactory.initializeSession(target));
            if (isStop()) {
                return;
            }

            ExtensionHttpsInfo extHttpsInfo =
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionHttpsInfo.class);
            String proxyChainWarning =
                    extHttpsInfo != null ? extHttpsInfo.getProxyChainWarning() : null;
            IX509Certificate cert = null;
            ICipherSuite[] ciphers = null;
            try {
                cert = engine.getCertificate();
                ciphers = engine.getCipherSuites();
            } catch (DeepVioletException e) {
                LOGGER.debug("Failed to get engine data: {}", e.getMessage());
            }
            String report = buildConfigReport(target.getHost(), proxyChainWarning, cert, ciphers);

            buildInfoAlert(baseMsg, null, report).raise();

            if (isStop()) {
                return;
            }

            raiseSecurityFailureAlertsIfNeeded(engine, baseMsg, report);

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

            IRiskScore.LetterGrade grade = riskScore.getLetterGrade();
            String gradeStr = grade != null ? grade.toDisplayString() : "N/A";
            String fullReport =
                    buildFailureReport(
                            String.valueOf(riskScore.getTotalScore()),
                            gradeStr,
                            failureDetails.toString(),
                            configReport);

            buildFailureAlert(baseMsg, null, fullReport, worstRiskLevel).raise();

        } catch (DeepVioletException e) {
            LOGGER.debug("Failed to compute risk score: {}", e.getMessage());
        }
    }

    private String buildFailureReport(
            String score, String grade, String failureDetails, String configReport) {
        StringBuilder report = new StringBuilder();
        report.append(Constant.messages.getString(MESSAGE_PREFIX + "failure.desc"));
        report.append(System.lineSeparator());
        report.append(Constant.messages.getString(MESSAGE_PREFIX + "failure.score", score));
        report.append(System.lineSeparator());
        report.append(Constant.messages.getString(MESSAGE_PREFIX + "failure.grade", grade));
        report.append(System.lineSeparator());
        report.append(System.lineSeparator());
        report.append(Constant.messages.getString(MESSAGE_PREFIX + "failure.findings"));
        report.append(failureDetails);
        report.append(System.lineSeparator());
        report.append(Constant.messages.getString(MESSAGE_PREFIX + "failure.config"));
        report.append(System.lineSeparator());
        report.append(configReport);
        return report.toString();
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

    private String buildConfigReport(
            String host, String proxyChainWarning, IX509Certificate cert, ICipherSuite[] ciphers) {
        StringBuilder report = new StringBuilder();
        if (proxyChainWarning != null) {
            report.append(proxyChainWarning)
                    .append(System.lineSeparator())
                    .append(System.lineSeparator());
        }
        report.append(Constant.messages.getString("httpsinfo.general.server.leadin", host));
        report.append(System.lineSeparator());

        if (cert != null) {
            report.append(Constant.messages.getString("httpsinfo.general.cert.heading"));
            report.append("  ");
            report.append(buildCertDetails(cert));
            report.append(System.lineSeparator());
        } else {
            report.append(Constant.messages.getString("httpsinfo.general.cert.notfound"));
        }

        if (ciphers != null && ciphers.length > 0) {
            report.append(Constant.messages.getString("httpsinfo.ciphersuites.supported.label"));
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

        return report.toString();
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

    private static final class ExampleICipherSuite implements ICipherSuite {
        private final String suiteName;
        private final String strengthEvaluation;
        private final String handshakeProtocol;

        ExampleICipherSuite(String suiteName, String strengthEvaluation, String handshakeProtocol) {
            this.suiteName = suiteName;
            this.strengthEvaluation = strengthEvaluation;
            this.handshakeProtocol = handshakeProtocol;
        }

        @Override
        public String getSuiteName() {
            return suiteName;
        }

        @Override
        public String getStrengthEvaluation() {
            return strengthEvaluation;
        }

        @Override
        public String getHandshakeProtocol() {
            return handshakeProtocol;
        }
    }

    private static final class ExampleIX509Certificate implements IX509Certificate {
        @Override
        public String getSubjectDN() {
            return "CN=example.com";
        }

        @Override
        public String getSigningAlgorithm() {
            return "SHA256withRSA";
        }

        @Override
        public String getCertificateFingerPrint() {
            return "AA:BB:CC:...";
        }

        @Override
        public String getIssuerDN() {
            return "CN=example.com";
        }

        @Override
        public String getNotValidBefore() {
            return "";
        }

        @Override
        public String getNotValidAfter() {
            return "";
        }

        @Override
        public BigInteger getCertificateSerialNumber() {
            return BigInteger.ZERO;
        }

        @Override
        public int getCertificateVersion() {
            return 3;
        }

        @Override
        public boolean isSelfSignedCertificate() {
            return false;
        }

        @Override
        public String getSigningAlgorithmOID() {
            return "";
        }

        @Override
        public ValidState getValidityState() {
            return ValidState.VALID;
        }

        @Override
        public TrustState getTrustState() {
            return TrustState.TRUSTED;
        }

        @Override
        public boolean isJavaRootCertificate() {
            return false;
        }

        @Override
        public String[] getNonCritOIDProperties() {
            return new String[0];
        }

        @Override
        public String getNonCritPropertyValue(String key) {
            return null;
        }

        @Override
        public boolean isContainsNonCritPropertyKey(String key) {
            return false;
        }

        @Override
        public String[] getCritOIDProperties() {
            return new String[0];
        }

        @Override
        public String getCritPropertyValue(String key) {
            return null;
        }

        @Override
        public boolean isContainsCritPropertyKey(String key) {
            return false;
        }

        @Override
        public IX509Certificate[] getCertificateChain() {
            return new IX509Certificate[0];
        }

        @Override
        public String getPublicKeyAlgorithm() {
            return "RSA";
        }

        @Override
        public int getPublicKeySize() {
            return 2048;
        }

        @Override
        public String getPublicKeyCurve() {
            return null;
        }

        @Override
        public long getDaysUntilExpiration() {
            return 365;
        }

        @Override
        public List<String> getSubjectAlternativeNames() {
            return List.of();
        }

        @Override
        public com.mps.deepviolet.api.IRevocationStatus getRevocationStatus() {
            return null;
        }
    }
}
