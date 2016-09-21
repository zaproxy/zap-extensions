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
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.text.MessageFormat;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
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

public class MDialog extends AbstractFrame {
	private static final long serialVersionUID = 6633774164518653658L;

	private static final String NEWLINE = "\n";
	
	private static final Logger LOGGER = Logger.getLogger(ExtensionHttpsInfo.class);

	private static final int BEAST_PLUGIN_ID = 10200;
	private static final int CRIME_PLUGIN_ID = 10201;

	private ExtensionAlert extensionAlert = (ExtensionAlert) Control.getSingleton().getExtensionLoader()
			.getExtension(ExtensionAlert.NAME);

	private boolean ordered = false;
	private Map<String, Integer> versionStrings;
	private SSLServer server;
	private HttpMessage baseMessage;

	private JTextArea general;
	private JLabel spinnerPref;
	private JTextArea cipherSuites;
	private JComboBox<String> suppVers;
	private JButton refresh;

	public MDialog(SSLServer s, HttpMessage msg) {
		super();
		this.server = s;
		this.baseMessage = msg;
		this.setIconImage(new ImageIcon(ExtensionHttpsInfo.class.getResource(ExtensionHttpsInfo.ICON_PATH)).getImage());
		this.setTitle(Constant.messages.getString("httpsinfo.name"));
		this.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
		this.centerFrame();
		init();
		addComponentsToPane(getContentPane());
		this.pack();
		updateContent();
		this.setVisible(true);
	}

	public void init() {
		checkProxyChainEnabled();
		
		general = new JTextArea();
		general.setEditable(false);
		general.setRows(10);
		general.setColumns(60);
		spinnerPref = new JLabel(Constant.messages.getString("httpsinfo.spinnerpref.label"));
		cipherSuites = new JTextArea();
		cipherSuites.setEditable(false);
		cipherSuites.setRows(10);
		cipherSuites.setColumns(60);
		refresh = new JButton(Constant.messages.getString("httpsinfo.serverpref.button"));
		refresh.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				new Thread(new Runnable() {
					@Override
					public void run() {
						refresh.setEnabled(false);
						server.orderCertificates();
						ordered = true;
						refresh.setVisible(false);
						updateContent();
					}
				}).start();
			}
		});
		versionStrings = new HashMap<String, Integer>();
		for (int v : server.getSupportedVersions()) {
			versionStrings.put(SSLServer.versionString(v), v);
		}
		Object[] list = versionStrings.keySet().toArray();
		String[] slist = new String[list.length];
		for (int i = 0; i < slist.length; i++) {
			slist[i] = list[i].toString();
		}
		Arrays.sort(slist);
		suppVers = new JComboBox<String>(slist);
		suppVers.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent arg0) {
				showCipherSuites();

			}
		});
	}

	public void updateContent() {
		showGeneral();
		showCipherSuites();
	}

	public void showGeneral() {
		StringBuilder content = new StringBuilder(
				Constant.messages.getString("httpsinfo.general.server.leadin", server.getServerName()));
		if (server.getCert().size() == 0) {
			content.append(Constant.messages.getString("httpsinfo.general.cert.notfound"));
			new Thread(new Runnable() {
				@Override
				public void run() {
					server.updateCertificate();
					showGeneral();
				}
			}).start();
		} else {
			content.append(Constant.messages.getString("httpsinfo.general.cert.heading"));
			for (String cc : server.getCert()) {
				content.append("  ").append(cc).append(NEWLINE);
			}
		}
		content.append(Constant.messages.getString("httpsinfo.general.deflate.heading")).append(" ");
		if (server.getDeflateCompression() == null) {
			content.append(Constant.messages.getString("httpsinfo.general.pending.indicator"));
			new Thread(new Runnable() {
				@Override
				public void run() {
					server.updateCompress();
					showGeneral();
				}
			}).start();
		} else {
			content.append((server.getDeflateCompression() ? Constant.messages.getString("httpsinfo.general.yes")
					: Constant.messages.getString("httpsinfo.general.no"))).append(NEWLINE);
		}
		if (server.getMinStrength() == null) {
			content.append(Constant.messages.getString("httpsinfo.general.minimum.strength.heading")).append(" ")
					.append(Constant.messages.getString("httpsinfo.general.pending.indicator"));
		} else {
			content.append(Constant.messages.getString("httpsinfo.general.minimum.strength.heading")).append(" ")
					.append(strengthString(server.getMinStrength())).append(NEWLINE);
		}
		if (server.getMaxStrength() == null) {
			content.append(Constant.messages.getString("httpsinfo.general.achieveable.strength.heading")).append(" ")
					.append(Constant.messages.getString("httpsinfo.general.pending.indicator"));
		} else {
			content.append(Constant.messages.getString("httpsinfo.general.achieveable.strength.heading")).append(" ")
					.append(strengthString(server.getMaxStrength())).append(NEWLINE);
		}
		if (server.getBeastVuln() == null) {
			content.append(Constant.messages.getString("httpsinfo.general.beast.status.heading")).append(" ")
					.append(Constant.messages.getString("httpsinfo.general.pending.indicator"));
		} else {
			content.append(Constant.messages.getString("httpsinfo.general.beast.status.heading")).append(" ")
					.append(server.getBeastVuln()
							? Constant.messages.getString("httpsinfo.general.vulnerable.indicator")
							: Constant.messages.getString("httpsinfo.general.protected.indicator"))
					.append(NEWLINE);
			if (server.getBeastVuln()) {
				raiseBeastAlert();
			}
		}
		if (server.getCrimeVuln() == null) {
			content.append(Constant.messages.getString("httpsinfo.general.crime.status.heading"))
					.append(Constant.messages.getString("httpsinfo.general.pending.indicator"));
		} else {
			content.append(Constant.messages.getString("httpsinfo.general.crime.status.heading")).append(" ")
					.append(server.getCrimeVuln()
							? Constant.messages.getString("httpsinfo.general.vulnerable.indicator")
							: Constant.messages.getString("httpsinfo.general.protected.indicator"));
			if (server.getCrimeVuln()) {
				raiseCrimeAlert();
			}
		}

		general.setText(content.toString());
	}

	public void showCipherSuites() {
		StringBuilder cs = new StringBuilder(Constant.messages.getString("httpsinfo.ciphersuites.supported.label"))
				.append(" ").append(suppVers.getSelectedItem()).append(" ")
				.append(ordered ? Constant.messages.getString("httpsinfo.ciphersuites.ordered")
						: Constant.messages.getString("httpsinfo.ciphersuites.unordered"));
		int x = 0;
		try {
			for (int c : server.getSupportedCipherSuites().get(versionStrings.get(suppVers.getSelectedItem()))) {
				String entry = ordered ? x + "." : "  ";
				cs.append(entry).append("      ").append(SSLServer.cipherSuiteString(c)).append(NEWLINE);
				x++;
			}

		} catch (Exception e) {
			cs.append("Pending...");
			new Thread(new Runnable() {
				@Override
				public void run() {
					server.updateSupportedCS();
					server.updateAttackVuln();
					server.updateStrength();
					showGeneral();
					showCipherSuites();
				}
			}).start();
		}
		cipherSuites.setText(cs.toString());
	}

	public void addComponentsToPane(Container pane) {
		pane.setLayout(new GridBagLayout());
		GridBagConstraints c = new GridBagConstraints();
		c.fill = GridBagConstraints.BOTH;
		c.gridwidth = 3;
		c.anchor = GridBagConstraints.NORTH;
		
		c.weighty = 0.5;
		c.gridx = 0;
		c.gridy = 0;
		pane.add(new JScrollPane(general), c);
		 
		c.gridwidth = 1;
		c.weightx = 0.5;
		c.weighty = 0;
		c.gridx = 0;
		c.gridy = 1;
		pane.add(spinnerPref, c);

		c.weightx = 0.5;
		c.gridx = 1;
		c.gridy = 1;
		pane.add(suppVers, c);

		c.weightx = 0.1;
		c.gridx = 2;
		c.gridy = 1;
		pane.add(refresh, c);
		
		c.gridx = 0;
		c.gridy = 2;
		c.gridwidth = 3;
		c.weighty = 0.5;
		c.anchor = GridBagConstraints.SOUTH;
		pane.add(new JScrollPane(cipherSuites), c);
	}

	private String strengthString(int strength) {
		switch (strength) {
		case 0:
			return Constant.messages.getString("httpsinfo.ciphersuites.no.enc");
		case 1:
			return Constant.messages.getString("httpsinfo.ciphersuites.weak.enc");
		case 2:
			return Constant.messages.getString("httpsinfo.ciphersuites.medium.enc");
		case 3:
			return Constant.messages.getString("httpsinfo.ciphersuites.strong.enc");
		default:
			LOGGER.info("strange strength: " + strength);
			return "";
		}
	}

	private void raiseBeastAlert() {
		Alert alert = new Alert(BEAST_PLUGIN_ID, Alert.RISK_INFO, Alert.CONFIDENCE_MEDIUM,
				Constant.messages.getString("httpsinfo.beast.name"));
		alert.setDetail(Constant.messages.getString("httpsinfo.beast.desc"), // Desc
				baseMessage.getRequestHeader().getURI().toString(), // URI
				null, // Param
				null, // Attack
				null, // OtherInfo
				Constant.messages.getString("httpsinfo.beast.soln"), // Solution
				Constant.messages.getString("httpsinfo.beast.refs"), // References
				null, // Evidence
				311, // CWE ID
				4, // WASC ID
				baseMessage); // HTTPMessage
		extensionAlert.alertFound(alert, baseMessage.getHistoryRef());
	}

	private void raiseCrimeAlert() {
		Alert alert = new Alert(CRIME_PLUGIN_ID, Alert.RISK_LOW, Alert.CONFIDENCE_MEDIUM,
				Constant.messages.getString("httpsinfo.crime.name"));
		alert.setDetail(Constant.messages.getString("httpsinfo.crime.desc"), // Desc
				baseMessage.getRequestHeader().getURI().toString(), // URI
				null, // Param
				null, // Attack
				null, // OtherInfo
				Constant.messages.getString("httpsinfo.crime.soln"), // Solution
				Constant.messages.getString("httpsinfo.crime.refs"), // References
				null, // Evidence
				311, // CWE ID
				4, // WASC ID
				baseMessage); // HTTPMessage
		extensionAlert.alertFound(alert, baseMessage.getHistoryRef());
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
}
