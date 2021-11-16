package org.zaproxy.zap.extension.httpsinfo;


import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.HostProcess;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.alert.ExtensionAlert;
import org.zaproxy.zap.extension.pscan.PassiveScanner;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashSet;
import java.util.Set;

import net.htmlparser.jericho.Source;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;
import com.mps.deepviolet.api.DVException;
import com.mps.deepviolet.api.DVFactory;
import com.mps.deepviolet.api.IDVCipherSuite;
import com.mps.deepviolet.api.IDVEng;
import com.mps.deepviolet.api.IDVSession;
import com.mps.deepviolet.api.IDVX509Certificate;


import java.util.HashMap;


public class HttpsInfoScanner implements PassiveScanner {
    private static final Logger LOGGER = LogManager.getLogger(HttpsInfoScanner.class);
    private HttpsInfoCertificationHolder certificationHolder;
    private Set<String> visitedSiteIdentifiers = new HashSet<>();

    private Certification currentCert;
    private CertificateFound certFound;
    private CipherSuite cipherSuite;
    private volatile boolean enabled = true;

    private IDVSession session;
    private IDVEng dvEng;
    private HttpMessage baseMessage;
    private URL target = null;


    private static final int BEAST_PLUGIN_ID = 10200;
    private static final int CRIME_PLUGIN_ID = 10201;

    private ExtensionAlert extensionAlert =
            Control.getSingleton().getExtensionLoader().getExtension(ExtensionAlert.class);


    public HttpsInfoScanner(HttpsInfoCertificationHolder certificationHolder) {
        super();
        this.certificationHolder = certificationHolder;
    }

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        String siteIdentifier = getSiteIdentifier(msg);

        if (siteIdentifier == null) {
            return;
        } else if (!visitedSiteIdentifiers.add(siteIdentifier)) {
            return;
        } else {
            long startTime = System.currentTimeMillis();
            checkHttpsInfo(msg);
            if (certFound != null) {
                String site = ExtensionHttpsInfo.normalizeSite(msg.getRequestHeader().getURI());

                addCertificationsToSite(site, certFound);
                this.certFound = null;
                this.currentCert = null;
            }
            LOGGER.debug("Analysis took {} ms", System.currentTimeMillis() - startTime);
        }
    }

    private String getSiteIdentifier(HttpMessage msg) {
        HistoryReference href = msg.getHistoryRef();
        if (href != null) {
            SiteNode node = href.getSiteNode();
            if (node != null) {
                if (node.getParent().isRoot()) {
                    return node.getHierarchicNodeName();
                }
            }
        }
        return null;
    }


    private void addCertificationsToSite(String site, CertificateFound certFound) {
        certificationHolder.addCertificationToSite(site, certFound);
    }


    private void checkHttpsInfo(HttpMessage msg) {
        setTarget(msg);
        setBaseMessage(msg);
        checkProxyChainEnabled();

        if (getTarget() == null) {
            String missingMsg =
                    Constant.messages.getString("httpsinfo.init.warning.missing");
            LOGGER.warn(missingMsg);
            View.getSingleton().showWarningDialog(missingMsg);
            return;
        }
        try {
            initSession(getTarget());
        } catch (DVException e) {
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
        } catch (DVException e) {
            LOGGER.warn(e.getMessage(), e);
        }
        setGeneral();
        setCipherSuites();
    }

    private void setTarget(HttpMessage msg) {
        try {
            this.target = new URL(msg.getRequestHeader().getURI().toString());
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

    private void initSession(URL target) throws DVException {
        try {
            this.session = DVFactory.initializeSession(target);
        } catch (DVException e) {
            throw new DVException(
                    "An exception occurred while initializing the DV session. " + e.getMessage(),
                    e.getCause());
        }
    }

    private IDVSession getSession() {
        return session;
    }

    private void setDvEng(IDVSession session) throws DVException {
        this.dvEng = DVFactory.getDVEng(session);
    }

    private IDVEng getDvEng() {
        return dvEng;
    }


    private void setGeneral() {
        try {
            if (getDvEng().getCertificate() == null) {
                LOGGER.warn(Constant.messages.getString("httpsinfo.general.cert.notfound"));
            } else {
                LOGGER.warn(Constant.messages.getString("httpsinfo.general.cert.heading"));
                setCertFound(getDvEng().getCertificate());
            }
        } catch (DVException e) {
            String generalException =
                    Constant.messages.getString("httpsinfo.general.exception", e.getMessage());
            LOGGER.warn(generalException, e);
        }
    }

    private void setCertFound(IDVX509Certificate cert) {
        this.currentCert = new Certification();
        this.currentCert.setSubjectDN(cert.getSubjectDN());
        this.currentCert.setSigningAlgorithm(cert.getSigningAlgorithm());
        this.currentCert.setCertificateFingerPrint(cert.getCertificateFingerPrint());
        this.currentCert.setIssuerDN(cert.getIssuerDN());
        this.currentCert.setNotValidBefore(cert.getNotValidBefore());
        this.currentCert.setNotValidAfter(cert.getNotValidAfter());
        this.currentCert.setCertificateSerialNumber(String.valueOf(cert.getCertificateSerialNumber()));
        this.currentCert.setCertificateVersion(String.valueOf(cert.getCertificateVersion()));
        this.currentCert.setSelfSignedCertificate(String.valueOf(cert.isSelfSignedCertificate()));
        this.currentCert.setTrustState(String.valueOf(cert.getTrustState()));
        this.currentCert.setValidState(String.valueOf(cert.getValidityState()));


        certFound = new CertificateFound(this.currentCert);
    }

    private void setCipherSuites() {


        IDVCipherSuite[] ciphers = null;
        try {
            ciphers = getDvEng().getCipherSuites();
        } catch (DVException e) {
            String cipherSuitesException =
                    Constant.messages.getString("httpsinfo.ciphersuites.exception", e.getMessage());
            LOGGER.warn(cipherSuitesException, e);
//            this.append(cipherSuitesException);
            return;
        }
        HashMap<IDVCipherSuite, IDVCipherSuite> csMap = new HashMap<>();

        for (IDVCipherSuite cipher : ciphers) {
            this.cipherSuite = new CipherSuite();
            // If cipher's in the map then skip since we already printed it. We
            // only want a unique list of ciphers.
            if (!csMap.containsKey(cipher)) {
                this.cipherSuite.setSuiteName(cipher.getSuiteName());
                this.cipherSuite.setStrengthEvaluation(cipher.getStrengthEvaluation());
                this.cipherSuite.setHandshakeProtocol(cipher.getHandshakeProtocol());
                csMap.put(cipher, cipher);
            }
            certFound.addCipherSuites(this.cipherSuite);
        }

    }

    /**
     * Check if ZAP is configured to use an outbound proxy. If it is then warn via a GUI dialog.
     * Results may be inaccurate, representing the connection to the proxy instead of the connection
     * to the target.
     */
    private void checkProxyChainEnabled() {
        if (Model.getSingleton().getOptionsParam().getConnectionParam().isUseProxyChain()) {
            String warningMsg =
                    Constant.messages.getString(
                            "httpsinfo.warn.outgoing.proxy.enabled",
                            Constant.messages.getString("httpsinfo.name"));
            View.getSingleton().showWarningDialog(warningMsg);
        }
    }

    @Override
    public void setParent(PassiveScanThread parent) {
    }

    @Override
    public String getName() {
        return Constant.messages.getString("httpsinfo.scanner");
    }

    @Override
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    @Override
    public boolean appliesToHistoryType(int historyType) {
        return PluginPassiveScanner.getDefaultHistoryTypes().contains(historyType);
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
