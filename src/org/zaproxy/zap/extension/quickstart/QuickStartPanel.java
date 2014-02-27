/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2012 The ZAP development team
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
package org.zaproxy.zap.extension.quickstart;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Event;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.KeyEvent;
import java.net.URL;

import javax.swing.BorderFactory;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.KeyStroke;
import javax.swing.border.EtchedBorder;

import org.apache.commons.httpclient.URI;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.control.Control.Mode;
import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.alert.ExtensionAlert;
import org.zaproxy.zap.extension.brk.BreakPanel;
import org.zaproxy.zap.extension.search.SearchPanel;
import org.zaproxy.zap.extension.tab.Tab;
import org.zaproxy.zap.utils.DesktopUtils;
import org.zaproxy.zap.utils.ZapTextField;
import org.zaproxy.zap.view.LayoutHelper;
import org.zaproxy.zap.view.NodeSelectDialog;

public class QuickStartPanel extends AbstractPanel implements Tab {

	private static final long serialVersionUID = 1L;

	private ExtensionQuickStart extension;
	private JButton attackButton = null;
	private JButton stopButton = null;
	private JButton confButton = null;
	private ZapTextField urlField = null;
	private ZapTextField confField = null;
	private JLabel progressLabel = null;

	public QuickStartPanel(ExtensionQuickStart extension) {
		super();
		this.extension = extension;
		initialize();
	}

	private void initialize() {
		this.setIcon(new ImageIcon(BreakPanel.class.getResource("/resource/icon/16/147.png")));	// 'lightning' icon
		this.setDefaultAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_Q, Event.CTRL_MASK | Event.SHIFT_MASK, false));
		this.setMnemonic(Constant.messages.getChar("quickstart.panel.mnemonic"));
		this.setLayout(new BorderLayout());

		JPanel panelContent = new JPanel(new GridBagLayout());
		JScrollPane jScrollPane = new JScrollPane();
		jScrollPane.setFont(new java.awt.Font("Dialog", java.awt.Font.PLAIN, 11));
		jScrollPane.setHorizontalScrollBarPolicy(javax.swing.JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
		jScrollPane.setViewportView(panelContent);

		this.add(jScrollPane, BorderLayout.CENTER);
		
		
		panelContent.setBackground(Color.white);
		panelContent.setBorder(BorderFactory.createEtchedBorder(EtchedBorder.RAISED));
		
		/*
		 * Layout:
		 * Col            0                      1                      2                    3                       4
		 * Row+----------------------+----------------------+----------------------+----------------------+----------------------+
		 *  0 | Top welcome message                                                                       |    zap128x128.png    |
		 *  1 | URL:                 | [ Url field                                                      ] |                      |
		 *  2 |                      | [ Attack button ]    | [ Stop button ]      | padding              |                      |
		 *  3 | Progress:            | Progress details                                                   |                      |
		 *    | Bottom message                                                                                                   |
		 *    | Show at start:       | [x]                  |                      |                      |                      |
		 *    +----------------------+----------------------+----------------------+----------------------+----------------------+
		 */

		panelContent.add(new JLabel(Constant.messages.getString("quickstart.panel.topmsg")), 
				LayoutHelper.getGBC(0, 0, 4, 1.0D, new Insets(5,5,5,5)));
		if (Constant.isDevBuild()) {
			panelContent.add(new JLabel(new ImageIcon(QuickStartPanel.class.getResource(
					"/org/zaproxy/zap/extension/quickstart/resource/zap128x128dark.png"))),
					LayoutHelper.getGBC(4, 0, 1, 0.0D, 0.0D, GridBagConstraints.NORTH));
		} else {
			panelContent.add(new JLabel(new ImageIcon(SearchPanel.class.getResource("/resource/zap128x128.png"))),
				LayoutHelper.getGBC(4, 0, 1, 0.0D, 0.0D, GridBagConstraints.NORTH));
		}
	
		panelContent.add(new JLabel(Constant.messages.getString("quickstart.label.url")), 
				LayoutHelper.getGBC(0, 1, 1, 0.0D, new Insets(5,5,5,5)));

		JPanel urlSelectPanel = new JPanel(new GridBagLayout());
		JButton selectButton = new JButton(Constant.messages.getString("all.button.select"));
		selectButton.setIcon(new ImageIcon(View.class.getResource("/resource/icon/16/094.png"))); // Globe icon
		selectButton.addActionListener(new java.awt.event.ActionListener() { 
			@Override
			public void actionPerformed(java.awt.event.ActionEvent e) {
				NodeSelectDialog nsd = new NodeSelectDialog(View.getSingleton().getMainFrame());
				SiteNode node = null; 
				try {
					node = Model.getSingleton().getSession().getSiteTree().findNode(new URI(getUrlField().getText(), false));
				} catch (Exception e2) {
					// Ignore
				}
				node = nsd.showDialog(node);
				if (node != null && node.getHistoryReference() != null) {
					try {
						getUrlField().setText(node.getHistoryReference().getURI().toString());
					} catch (Exception e1) {
						// Ignore
					}
				}
			}
		});
		
		urlSelectPanel.add(this.getUrlField(), LayoutHelper.getGBC(0, 0, 1, 1.0D));
		urlSelectPanel.add(selectButton, LayoutHelper.getGBC(1, 0, 1, 0.0D));
		panelContent.add(urlSelectPanel, LayoutHelper.getGBC(1, 1, 3, 0.25D));
		
		panelContent.add(this.getAttackButton(), LayoutHelper.getGBC(1, 2, 1, 0.0D));
		panelContent.add(this.getStopButton(), LayoutHelper.getGBC(2, 2, 1, 0.0D));
		panelContent.add(new JLabel(""), LayoutHelper.getGBC(3, 2, 1, 0.75D, 0.0D));	// Padding to right of buttons
		
		progressLabel = new JLabel(Constant.messages.getString("quickstart.progress." + AttackThread.Progress.notstarted.name()));
		panelContent.add(new JLabel(Constant.messages.getString("quickstart.label.progress")), 
				LayoutHelper.getGBC(0, 3, 1, 0.0D, new Insets(5,5,5,5)));
		panelContent.add(this.progressLabel, LayoutHelper.getGBC(1, 3, 3, 0.0D));

		panelContent.add(new JLabel(Constant.messages.getString("quickstart.panel.proxymsg")), 
				LayoutHelper.getGBC(0, 4, 5, 1.0D, new Insets(5,5,5,5)));

		if (Control.getSingleton().getExtensionLoader().getExtension("ExtensionPlugNHack") != null) {
			// Plug-n-Hack extension has been installed - this makes configuration much easier :)
			if (DesktopUtils.canOpenUrlInBrowser()) {
				panelContent.add(new JLabel(Constant.messages.getString("quickstart.label.mitm")), 
						LayoutHelper.getGBC(0, 6, 1, 0.0D, new Insets(5,5,5,5)));
				panelContent.add(this.getConfButton(), LayoutHelper.getGBC(1, 6, 1, 0.0D));

				panelContent.add(new JLabel(
						Constant.messages.getString("quickstart.label.mitmalt")),
						LayoutHelper.getGBC(0, 7, 1, 0.0D, new Insets(5,5,5,5)));
			} else {
				panelContent.add(new JLabel(
						Constant.messages.getString("quickstart.label.mitmurl")),
						LayoutHelper.getGBC(0, 7, 1, 0.0D, new Insets(5,5,5,5)));
			}
			panelContent.add(this.getConfField(), LayoutHelper.getGBC(1, 7, 3, 0.25D));
			
		} else {
			panelContent.add(new JLabel(Constant.messages.getString("quickstart.panel.helpmsg")), 
					LayoutHelper.getGBC(0, 5, 5, 1.0D, new Insets(5,5,5,5)));
			
		}
		
		panelContent.add(new JLabel(""), LayoutHelper.getGBC(0, 10, 4, 1.D, 1.0D));	// Padding at bottom
		
		this.setMode(Control.getSingleton().getMode());
	}
	
	protected void setMode(Mode mode) {
		this.getUrlField().setEditable(mode.equals(Mode.standard));
		this.getAttackButton().setEnabled(mode.equals(Mode.standard));
	}
	
	private ZapTextField getUrlField () {
		if (urlField == null) {
			urlField = new ZapTextField();
			urlField.setText("http://");
		}
		return urlField;
	}
	
	private JButton getAttackButton() {
		if (attackButton == null) {
			attackButton = new JButton();
			attackButton.setText(Constant.messages.getString("quickstart.button.label.attack"));
			attackButton.setIcon(new ImageIcon(SearchPanel.class.getResource("/resource/icon/16/147.png")));	// 'lightning' icon
			attackButton.setToolTipText(Constant.messages.getString("quickstart.button.tooltip.attack"));

			attackButton.addActionListener(new java.awt.event.ActionListener() { 
				@Override
				public void actionPerformed(java.awt.event.ActionEvent e) {
					attackUrl();
				}
			});
		}
		return attackButton;
	}
	
	private JButton getStopButton() {
		if (stopButton == null) {
			stopButton = new JButton();
			stopButton.setText(Constant.messages.getString("quickstart.button.label.stop"));
			stopButton.setIcon(new ImageIcon(SearchPanel.class.getResource("/resource/icon/16/142.png")));	// 'stop' icon
			stopButton.setToolTipText(Constant.messages.getString("quickstart.button.tooltip.stop"));
			stopButton.setEnabled(false);

			stopButton.addActionListener(new java.awt.event.ActionListener() { 
				@Override
				public void actionPerformed(java.awt.event.ActionEvent e) {
					stopAttack();
				}
			});
		}
		return stopButton;
	}
	
	private String getPlugNHackUrl() {
		return "http://" + Model.getSingleton().getOptionsParam().getProxyParam().getProxyIp() + ":" + 
				Model.getSingleton().getOptionsParam().getProxyParam().getProxyPort() + "/pnh/"; 
	}

	private ZapTextField getConfField () {
		if (confField == null) {
			confField = new ZapTextField();
			confField.setText(getPlugNHackUrl());
			confField.setEditable(false);
		}
		return confField;
	}
	
	private JButton getConfButton() {
		if (confButton == null) {
			confButton = new JButton();
			confButton.setText(Constant.messages.getString("quickstart.button.label.mitm"));
			confButton.setToolTipText(Constant.messages.getString("quickstart.button.tooltip.mitm"));
			confButton.setIcon(new ImageIcon(
					QuickStartPanel.class.getResource("/org/zaproxy/zap/extension/quickstart/resource/plug.png")));

			confButton.addActionListener(new java.awt.event.ActionListener() { 
				@Override
				public void actionPerformed(java.awt.event.ActionEvent e) {
					DesktopUtils.openUrlInBrowser(getPlugNHackUrl());
				}
			});
		}
		return confButton;
	}

	private void attackUrl () {
		URL url;
		try {
			url = new URL(this.getUrlField().getText());
		} catch (Exception e) {
			extension.getView().showWarningDialog(Constant.messages.getString("quickstart.url.warning.invalid"));
			return;
		}
		getAttackButton().setEnabled(false);
		getStopButton().setEnabled(true);
		
		extension.attack(url);
	}
	
	private void stopAttack() {
		extension.stopAttack();
		
		stopButton.setEnabled(false);
	}

	protected void notifyProgress(AttackThread.Progress progress) {
		progressLabel.setText(Constant.messages.getString("quickstart.progress." + progress.name()));
		switch (progress) {
		case complete:
			getAttackButton().setEnabled(true);
			getStopButton().setEnabled(false);
			ExtensionAlert extAlert = ((ExtensionAlert)Control.getSingleton().getExtensionLoader().getExtension(ExtensionAlert.NAME));
			if (extAlert != null) {
				extAlert.setAlertTabFocus();
			}
			break;
		case failed:
		case stopped:
			getAttackButton().setEnabled(true);
			getStopButton().setEnabled(false);
			break;
		default:
			break;
		}
	}
	
}
