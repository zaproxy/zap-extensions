/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2017 The ZAP Development Team
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
import com.mps.deepviolet.api.ISession;
import com.mps.deepviolet.api.IX509Certificate;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.HashMap;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.OutputPanel;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.alert.ExtensionAlert;

@SuppressWarnings("serial")
public class HttpsInfoOutputPanel extends OutputPanel {

    private static final long serialVersionUID = 906303747541635042L;

    private static final String NEWLINE = System.lineSeparator();

    private static final Logger LOGGER = LogManager.getLogger(HttpsInfoOutputPanel.class);

    private static final int BEAST_PLUGIN_ID = 10200;
    private static final int CRIME_PLUGIN_ID = 10201;

    private ExtensionAlert extensionAlert =
            Control.getSingleton().getExtensionLoader().getExtension(ExtensionAlert.class);

    private ISession session;
    private IEngine dvEng;
    private HttpMessage baseMessage;
    private URL target = null;

    public HttpsInfoOutputPanel(HttpMessage msg) {
        super();

        setTarget(msg);
        setBaseMessage(msg);
        doThreadedTasks();
    }

    private void setTarget(HttpMessage msg) {
        try {
            this.target = URI.create(msg.getRequestHeader().getURI().toString()).toURL();
        } catch (MalformedURLException e) {
            LOGGER.warn("An exception occurred while attempting to set the target", e);
        }
    }

    private URL getTarget() {
        if (target == null) {
            LOGGER.warn("Somehow the target was not set, when we tried to use it.");
            return null;
        }
        return target;
    }

    private void setBaseMessage(HttpMessage msg) {
        this.baseMessage = msg;
    }

    private HttpMessage getBaseMessage() {
        return baseMessage;
    }

    private void initSession(URL target) throws DeepVioletException {
        try {
            this.session = DeepVioletFactory.initializeSession(target);
        } catch (DeepVioletException e) {
            throw new DeepVioletException(
                    "An exception occurred while initializing the DV session. " + e.getMessage(),
                    e.getCause());
        }
    }

    private ISession getSession() {
        return session;
    }

    private void setDvEng(ISession session) throws DeepVioletException {
        this.dvEng = DeepVioletFactory.getEngine(session);
    }

    private IEngine getDvEng() {
        return dvEng;
    }

    private void doThreadedTasks() {
        Thread httpsInfoThread =
                new Thread("ZAP-httpsinfo") {
                    @Override
                    public void run() {
                        if (getTarget() == null) {
                            String missingMsg =
                                    Constant.messages.getString("httpsinfo.init.warning.missing");
                            LOGGER.warn(missingMsg);
                            View.getSingleton().showWarningDialog(missingMsg);
                            return;
                        }
                        try {
                            initSession(getTarget());
                        } catch (DeepVioletException e) {
                            String warnMsg =
                                    Constant.messages.getString(
                                            "httpsinfo.init.warning",
                                            getTarget().toString(),
                                            e.getCause());
                            LOGGER.warn(warnMsg);
                            View.getSingleton().showWarningDialog(warnMsg);
                            return;
                        }
                        try {
                            setDvEng(getSession());
                        } catch (DeepVioletException e) {
                            LOGGER.warn(e.getMessage(), e);
                        }
                        showGeneral();
                        showCipherSuites();
                    }
                };
        httpsInfoThread.start();
    }

    private void showGeneral() {
        StringBuilder content = new StringBuilder();
        ExtensionHttpsInfo extHttpsInfo =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionHttpsInfo.class);
        String proxyChainWarning =
                extHttpsInfo != null ? extHttpsInfo.getProxyChainWarning() : null;
        if (proxyChainWarning != null) {
            content.append(proxyChainWarning).append(NEWLINE).append(NEWLINE);
        }
        content.append(
                Constant.messages.getString("httpsinfo.general.server.leadin", target.getHost()));
        try {
            if (getDvEng().getCertificate() == null) {
                content.append(Constant.messages.getString("httpsinfo.general.cert.notfound"));
            } else {
                content.append(Constant.messages.getString("httpsinfo.general.cert.heading"));
                content.append("  ")
                        .append(getCleanCertStringRepresentation(getDvEng().getCertificate()))
                        .append(NEWLINE);
            }
        } catch (DeepVioletException e) {
            String generalException =
                    Constant.messages.getString("httpsinfo.general.exception", e.getMessage());
            LOGGER.warn(generalException, e);
            this.append(generalException);
            return;
        }

        this.append(content.toString());
    }

    private String getCleanCertStringRepresentation(IX509Certificate cert) {
        StringBuilder certRepresentation = new StringBuilder();
        final char SPACE = ' ';

        certRepresentation
                .append(Constant.messages.getString("httpsinfo.general.subject.dn"))
                .append(SPACE)
                .append(cert.getSubjectDN())
                .append(NEWLINE);
        certRepresentation
                .append(Constant.messages.getString("httpsinfo.general.signing.algo"))
                .append(SPACE)
                .append(cert.getSigningAlgorithm())
                .append(NEWLINE);
        certRepresentation
                .append(Constant.messages.getString("httpsinfo.general.cert.fingerprint"))
                .append(SPACE)
                .append(cert.getCertificateFingerPrint())
                .append(NEWLINE);
        certRepresentation
                .append(Constant.messages.getString("httpsinfo.general.issuer.dn"))
                .append(SPACE)
                .append(cert.getIssuerDN())
                .append(NEWLINE);
        certRepresentation
                .append(Constant.messages.getString("httpsinfo.general.not.valid.before"))
                .append(SPACE)
                .append(cert.getNotValidBefore())
                .append(NEWLINE);
        certRepresentation
                .append(Constant.messages.getString("httpsinfo.general.not.valid.after"))
                .append(SPACE)
                .append(cert.getNotValidAfter())
                .append(NEWLINE);
        certRepresentation
                .append(Constant.messages.getString("httpsinfo.general.cert.serial.number"))
                .append(SPACE)
                .append(cert.getCertificateSerialNumber().toString())
                .append(NEWLINE);
        certRepresentation
                .append(Constant.messages.getString("httpsinfo.general.cert.version"))
                .append(SPACE)
                .append(cert.getCertificateVersion())
                .append(NEWLINE);
        certRepresentation
                .append(Constant.messages.getString("httpsinfo.general.cert.self.signed"))
                .append(SPACE)
                .append(String.valueOf(cert.isSelfSignedCertificate()))
                .append(NEWLINE);

        return certRepresentation.toString();
    }

    private void showCipherSuites() {
        StringBuilder cs =
                new StringBuilder(
                        Constant.messages.getString("httpsinfo.ciphersuites.supported.label"));
        cs.append(NEWLINE);

        ICipherSuite[] ciphers = null;
        try {
            ciphers = getDvEng().getCipherSuites();
        } catch (DeepVioletException e) {
            String cipherSuitesException =
                    Constant.messages.getString("httpsinfo.ciphersuites.exception", e.getMessage());
            LOGGER.warn(cipherSuitesException, e);
            this.append(cipherSuitesException);
            return;
        }
        HashMap<ICipherSuite, ICipherSuite> csMap = new HashMap<>();

        for (ICipherSuite cipher : ciphers) {
            // If cipher's in the map then skip since we already printed it. We
            // only want a unique list of ciphers.
            if (!csMap.containsKey(cipher)) {
                cs.append(cipher.getSuiteName());
                cs.append('(');
                cs.append(cipher.getStrengthEvaluation());
                cs.append(',');
                cs.append(cipher.getHandshakeProtocol());
                cs.append(')');
                cs.append(NEWLINE);
                csMap.put(cipher, cipher);
            }
        }
        this.append(cs.toString());
    }

    /**
     * The following raise__Alert methods are being left in the code base for the time being. Though
     * DeepViolet does not currently have checks for Beast and Crime they may come back, or be
     * otherwise implemented.
     */
    @SuppressWarnings("unused")
    private void raiseBeastAlert() {
        Alert alert =
                Alert.builder()
                        .setPluginId(BEAST_PLUGIN_ID)
                        .setRisk(Alert.RISK_INFO)
                        .setConfidence(Alert.CONFIDENCE_MEDIUM)
                        .setName(Constant.messages.getString("httpsinfo.beast.name"))
                        .setDescription(Constant.messages.getString("httpsinfo.beast.desc"))
                        .setSolution(Constant.messages.getString("httpsinfo.beast.soln"))
                        .setReference(Constant.messages.getString("httpsinfo.beast.refs"))
                        .setCweId(311)
                        .setWascId(4)
                        .setMessage(getBaseMessage())
                        .build();

        extensionAlert.alertFound(alert, getBaseMessage().getHistoryRef());
    }

    @SuppressWarnings("unused")
    private void raiseCrimeAlert() {
        Alert alert =
                Alert.builder()
                        .setPluginId(CRIME_PLUGIN_ID)
                        .setRisk(Alert.RISK_LOW)
                        .setConfidence(Alert.CONFIDENCE_MEDIUM)
                        .setName(Constant.messages.getString("httpsinfo.crime.name"))
                        .setDescription(Constant.messages.getString("httpsinfo.crime.desc"))
                        .setSolution(Constant.messages.getString("httpsinfo.crime.soln"))
                        .setReference(Constant.messages.getString("httpsinfo.crime.refs"))
                        .setCweId(311)
                        .setWascId(4)
                        .setMessage(getBaseMessage())
                        .build();

        extensionAlert.alertFound(alert, getBaseMessage().getHistoryRef());
    }
}
