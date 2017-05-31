/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
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
package org.zaproxy.zap.extension.httpsinfo;

import java.awt.Container;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.net.MalformedURLException;
import java.net.URL;
import java.text.MessageFormat;
import java.util.HashMap;

import javax.swing.ImageIcon;
import javax.swing.JFrame;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.AbstractFrame;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.alert.ExtensionAlert;

import com.mps.deepviolet.api.DVException;
import com.mps.deepviolet.api.DVFactory;
import com.mps.deepviolet.api.IDVCipherSuite;
import com.mps.deepviolet.api.IDVEng;
import com.mps.deepviolet.api.IDVSession;
import com.mps.deepviolet.api.IDVX509Certificate;

public class HttpsInfoDialog extends AbstractFrame {
	private static final long serialVersionUID = 6633774164518653658L;

	private static final String NEWLINE = System.lineSeparator();
	
	private static final Logger LOGGER = Logger.getLogger(ExtensionHttpsInfo.class);

	private static final int BEAST_PLUGIN_ID = 10200;
	private static final int CRIME_PLUGIN_ID = 10201;

	private ExtensionAlert extensionAlert = Control.getSingleton().getExtensionLoader()
			.getExtension(ExtensionAlert.class);

	private IDVSession session;
	private IDVEng dvEng;
	private HttpMessage baseMessage;
	private URL target = null;

	private JTextArea general;
	private JTextArea cipherSuites; 

	public HttpsInfoDialog(HttpMessage msg) {
		super();
		
		setTarget(msg);
		setBaseMessage(msg);
	
		this.setIconImage(new ImageIcon(ExtensionHttpsInfo.class.getResource(ExtensionHttpsInfo.ICON_PATH)).getImage());
		this.setTitle(Constant.messages.getString("httpsinfo.name"));
		this.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
		this.centerFrame();
		init();
		addComponentsToPane(getContentPane());
		this.pack();
		this.setVisible(true);
		doThreadedTasks();
	}
	
	private JTextArea getGeneralTextArea() {
		return general;
	}
	
	private JTextArea getCipherSuitesTextArea() {
		return cipherSuites;
	}

	public void init() {
		checkProxyChainEnabled();
		
		initGeneral();
		initCipherSuites();
	}
	
	private void initGeneral() {
		general = new JTextArea();
		general.setEditable(false);
		general.setRows(12);
		general.setColumns(70);
		general.setLineWrap(true);
	}
	
	private void initCipherSuites() {
		cipherSuites = new JTextArea();
		cipherSuites.setEditable(false);
		cipherSuites.setRows(15);
		cipherSuites.setColumns(70);
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
			throw new DVException("An exception occurred while initializing the DV session. " + e.getMessage(),
					e.getCause());
		}
	}
	
	private IDVSession getSession() {
		return session;
	}
	
	private void setDvEng(IDVSession session) {
		this.dvEng = DVFactory.getDVEng(session);
	}
	
	private IDVEng getDvEng() {
		return dvEng;
	}
	
	private void doThreadedTasks() {
		Thread httpsInfoThread = new Thread("ZAP-httpsinfo") {
			@Override
			public void run() {
				try {
					initSession(getTarget());
				} catch (DVException e) {
					String warnMsg = Constant.messages.getString("httpsinfo.init.warning", getTarget().toString(),
							e.getCause()); 
					LOGGER.warn(warnMsg);
					getGeneralTextArea().setText(warnMsg);
					return;
				}
				setDvEng(getSession());
				showGeneral();
				showCipherSuites();
			}
		};
		httpsInfoThread.start();
	}

	private void showGeneral() {
		StringBuilder content = new StringBuilder(
				Constant.messages.getString("httpsinfo.general.server.leadin", target.getHost()));
		try {
			if (getDvEng().getCertificate() == null) {
				content.append(Constant.messages.getString("httpsinfo.general.cert.notfound"));
			} else {
				content.append(Constant.messages.getString("httpsinfo.general.cert.heading"));
				content.append("  ").append(getCleanCertStringRepresentation(getDvEng().getCertificate())).append(NEWLINE);
			}
		} catch (DVException e) {
			String generalException = Constant.messages.getString("httpsinfo.general.exception",
					e.getMessage());
			LOGGER.warn(generalException, e);
			getGeneralTextArea().setText(generalException);
			return;
		}

		general.setText(content.toString());
		general.setCaretPosition(0);
	}
	
	private String getCleanCertStringRepresentation(IDVX509Certificate cert) {
		StringBuilder certRepresentation = new StringBuilder();
		final char SPACE = ' ';
		
		certRepresentation.append(Constant.messages.getString("httpsinfo.general.subject.dn")).append(SPACE)
				.append(cert.getSubjectDN()).append(NEWLINE);
		certRepresentation.append(Constant.messages.getString("httpsinfo.general.signing.algo")).append(SPACE)
				.append(cert.getSigningAlgorithm()).append(NEWLINE);
		certRepresentation.append(Constant.messages.getString("httpsinfo.general.cert.fingerprint")).append(SPACE)
				.append(cert.getCertificateFingerPrint()).append(NEWLINE);
		certRepresentation.append(Constant.messages.getString("httpsinfo.general.issuer.dn")).append(SPACE)
				.append(cert.getIssuerDN()).append(NEWLINE);
		certRepresentation.append(Constant.messages.getString("httpsinfo.general.not.valid.before")).append(SPACE)
				.append(cert.getNotValidBefore()).append(NEWLINE);
		certRepresentation.append(Constant.messages.getString("httpsinfo.general.not.valid.after")).append(SPACE)
				.append(cert.getNotValidAfter()).append(NEWLINE);
		certRepresentation.append(Constant.messages.getString("httpsinfo.general.cert.serial.number")).append(SPACE)
				.append(cert.getCertificateSerialNumber()).append(NEWLINE);
		certRepresentation.append(Constant.messages.getString("httpsinfo.general.cert.version")).append(SPACE)
				.append(cert.getCertificateVersion()).append(NEWLINE);
		certRepresentation.append(Constant.messages.getString("httpsinfo.general.cert.self.signed")).append(SPACE)
				.append(String.valueOf(cert.isSelfSignedCertificate())).append(NEWLINE);
		
		return certRepresentation.toString();
	}

	private void showCipherSuites() {
		StringBuilder cs = new StringBuilder(Constant.messages.getString("httpsinfo.ciphersuites.supported.label"));
		cs.append(NEWLINE);
		
		IDVCipherSuite[] ciphers = null;
		try {
			ciphers = getDvEng().getCipherSuites();
		} catch (DVException e) {
			String cipherSuitesException = Constant.messages.getString("httpsinfo.ciphersuites.exception",
					e.getMessage());
			LOGGER.warn(cipherSuitesException, e);
			getCipherSuitesTextArea().setText(cipherSuitesException);
			return;
		}
		HashMap<IDVCipherSuite, IDVCipherSuite> csMap = new HashMap<IDVCipherSuite, IDVCipherSuite>();

		for (IDVCipherSuite cipher : ciphers) {
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
		cipherSuites.setText(cs.toString());
		cipherSuites.setCaretPosition(0);
	}

	public void addComponentsToPane(Container pane) {
		pane.setLayout(new GridBagLayout());
		GridBagConstraints c = new GridBagConstraints();
		c.fill = GridBagConstraints.BOTH;
		c.gridwidth = 1;
		c.weightx = 1.0;		
		c.weighty = 0.5;
		
		c.gridx = 0;
		c.gridy = 0;
		c.anchor = GridBagConstraints.NORTH;
		pane.add(new JScrollPane(general), c);
		
		c.gridx = 0;
		c.gridy = 1;
		c.gridwidth = 3;
		c.anchor = GridBagConstraints.SOUTH;
		pane.add(new JScrollPane(cipherSuites), c);
	}

	/**
	 * Check if ZAP is configured to use an outbound proxy. If it is then warn via a GUI dialog. 
	 * Results may be inaccurate, representing the connection to the proxy instead of the 
	 * connection to the target.
	 */
	private void checkProxyChainEnabled() {
		if (Model.getSingleton().getOptionsParam().getConnectionParam().isUseProxyChain()) {
			String warningMsg = MessageFormat.format(
					Constant.messages.getString("httpsinfo.warn.outgoing.proxy.enabled"),
					Constant.messages.getString("httpsinfo.name"));
			View.getSingleton().showWarningDialog(warningMsg);
		}
	}
	
	/**
	 * The following raise__Alert methods are being left in the code base for the time being.
	 * Though DeepViolet does not currently have checks for Beast and Crime they may come back, or be
	 * otherwise implemented.
	 */
	
	@SuppressWarnings("unused")
	private void raiseBeastAlert() {
		Alert alert = new Alert(BEAST_PLUGIN_ID, Alert.RISK_INFO, Alert.CONFIDENCE_MEDIUM,
				Constant.messages.getString("httpsinfo.beast.name"));
		alert.setDetail(Constant.messages.getString("httpsinfo.beast.desc"), // Desc
				getBaseMessage().getRequestHeader().getURI().toString(), // URI
				null, // Param
				null, // Attack
				null, // OtherInfo
				Constant.messages.getString("httpsinfo.beast.soln"), // Solution
				Constant.messages.getString("httpsinfo.beast.refs"), // References
				null, // Evidence
				311, // CWE ID
				4, // WASC ID
				getBaseMessage()); // HTTPMessage
		extensionAlert.alertFound(alert, getBaseMessage().getHistoryRef());
	}

	@SuppressWarnings("unused")
	private void raiseCrimeAlert() {
		Alert alert = new Alert(CRIME_PLUGIN_ID, Alert.RISK_LOW, Alert.CONFIDENCE_MEDIUM,
				Constant.messages.getString("httpsinfo.crime.name"));
		alert.setDetail(Constant.messages.getString("httpsinfo.crime.desc"), // Desc
				getBaseMessage().getRequestHeader().getURI().toString(), // URI
				null, // Param
				null, // Attack
				null, // OtherInfo
				Constant.messages.getString("httpsinfo.crime.soln"), // Solution
				Constant.messages.getString("httpsinfo.crime.refs"), // References
				null, // Evidence
				311, // CWE ID
				4, // WASC ID
				getBaseMessage()); // HTTPMessage
		extensionAlert.alertFound(alert, getBaseMessage().getHistoryRef());
	}
	
}
