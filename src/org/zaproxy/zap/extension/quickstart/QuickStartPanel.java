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
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Toolkit;
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
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.utils.ZapTextField;
import org.zaproxy.zap.view.LayoutHelper;
import org.zaproxy.zap.view.NodeSelectDialog;

public class QuickStartPanel extends AbstractPanel implements Tab {

	private static final long serialVersionUID = 1L;

	private ExtensionQuickStart extension;
	private JButton attackButton = null;
	private JButton stopButton = null;
	private ZapTextField urlField = null;
	private JLabel progressLabel = null;
	private JPanel panelContent = null;
	private JLabel lowerPadding = new JLabel("");
	private int panelY = 0;

	public QuickStartPanel(ExtensionQuickStart extension) {
		super();
		this.extension = extension;
		initialize();
	}

	@SuppressWarnings("deprecation")
	private void initialize() {
		this.setShowByDefault(true);
		this.setIcon(new ImageIcon(BreakPanel.class.getResource("/resource/icon/16/147.png")));	// 'lightning' icon
		// TODO Use getMenuShortcutKeyMaskEx() (and remove warn suppression) when targeting Java 10+
		this.setDefaultAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_Q, Toolkit.getDefaultToolkit().getMenuShortcutKeyMask() | KeyEvent.SHIFT_DOWN_MASK, false));
		this.setMnemonic(Constant.messages.getChar("quickstart.panel.mnemonic"));
		this.setLayout(new BorderLayout());

		panelContent = new JPanel(new GridBagLayout());
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
				LayoutHelper.getGBC(0, panelY, 4, 1.0D, new Insets(5,5,5,5)));
		if (Constant.isDevBuild()) {
			panelContent.add(new JLabel(new ImageIcon(QuickStartPanel.class.getResource(
					"/org/zaproxy/zap/extension/quickstart/resources/zap128x128dark.png"))),
					LayoutHelper.getGBC(4, panelY, 1, 0.0D, 0.0D, GridBagConstraints.NORTH));
		} else {
			panelContent.add(new JLabel(DisplayUtils.getScaledIcon(new ImageIcon(SearchPanel.class.getResource("/resource/zap128x128.png")))),
				LayoutHelper.getGBC(4, panelY, 1, 0.0D, 0.0D, GridBagConstraints.NORTH));
		}
	
		panelContent.add(new JLabel(Constant.messages.getString("quickstart.label.url")), 
				LayoutHelper.getGBC(0, ++panelY, 1, 0.0D, new Insets(5,5,5,5)));

		JPanel urlSelectPanel = new JPanel(new GridBagLayout());
		JButton selectButton = new JButton(Constant.messages.getString("all.button.select"));
		selectButton.setIcon(DisplayUtils.getScaledIcon(new ImageIcon(View.class.getResource("/resource/icon/16/094.png")))); // Globe icon
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
		panelContent.add(urlSelectPanel, LayoutHelper.getGBC(1, panelY, 3, 0.25D));
		
		panelContent.add(this.getAttackButton(), LayoutHelper.getGBC(1, ++panelY, 1, 0.0D));
		panelContent.add(this.getStopButton(), LayoutHelper.getGBC(2, panelY, 1, 0.0D));
		panelContent.add(new JLabel(""), LayoutHelper.getGBC(3, panelY, 1, 0.75D, 0.0D));	// Padding to right of buttons
		
		progressLabel = new JLabel(Constant.messages.getString("quickstart.progress." + AttackThread.Progress.notstarted.name()));
		panelContent.add(new JLabel(Constant.messages.getString("quickstart.label.progress")), 
				LayoutHelper.getGBC(0, ++panelY, 1, 0.0D, new Insets(5,5,5,5)));
		panelContent.add(this.progressLabel, LayoutHelper.getGBC(1, panelY, 3, 0.0D));

		panelContent.add(new JLabel(Constant.messages.getString("quickstart.panel.proxymsg")), 
				LayoutHelper.getGBC(0, ++panelY, 5, 1.0D, new Insets(5,5,5,5)));

		for (QuickStartPanelContentProvider provider : extension.getContentProviders()) {
		    this.addContent(provider);
		}
		replacePadding();
		
		this.setMode(Control.getSingleton().getMode());
	}
	
	private void replacePadding() {
	    if (panelContent != null) {
	        // this may or may not be present
	        panelContent.remove(this.lowerPadding);
	        panelContent.add(this.lowerPadding, LayoutHelper.getGBC(0, ++panelY, 4, 1.D, 1.0D));    // Padding at bottom
	    }
	}
	
	protected void addContent(QuickStartPanelContentProvider provider) {
        if (panelContent != null) {
            panelY = provider.addToPanel(panelContent, panelY);
            replacePadding();
        }
	}
	
    protected void removeContent(QuickStartPanelContentProvider provider) {
        if (panelContent != null) {
            provider.removeFromPanel(panelContent);
        }
	    
	}
	
	protected void setMode(Mode mode) {
		switch (mode) {
		case safe:
		case protect:
			this.getUrlField().setEditable(false);
			this.getAttackButton().setEnabled(false);
			break;
		case standard:
		case attack:
			this.getUrlField().setEditable(true);
			this.getAttackButton().setEnabled(true);
			break;
		}
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
			attackButton.setIcon(DisplayUtils.getScaledIcon(new ImageIcon(SearchPanel.class.getResource("/resource/icon/16/147.png"))));	// 'lightning' icon
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
			stopButton.setIcon(DisplayUtils.getScaledIcon(new ImageIcon(SearchPanel.class.getResource("/resource/icon/16/142.png"))));	// 'stop' icon
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
	
	

	boolean attackUrl () {
		URL url;
		try {
			url = new URL(this.getUrlField().getText());
			// Validate the actual request-uri of the HTTP message accessed.
			new URI(this.getUrlField().getText(), true);
		} catch (Exception e) {
			extension.getView().showWarningDialog(Constant.messages.getString("quickstart.url.warning.invalid"));
			this.getUrlField().requestFocusInWindow();
			return false;
		}
		getAttackButton().setEnabled(false);
		getStopButton().setEnabled(true);
		
		extension.attack(url);
		return true;
	}

	void setAttackUrl(String url) {
		getUrlField().setText(url);
	}
	
	private void stopAttack() {
		extension.stopAttack();
		
		stopButton.setEnabled(false);
	}

	protected void notifyProgress(AttackThread.Progress progress) {
		this.notifyProgress(progress, null);
	}

	protected void notifyProgress(AttackThread.Progress progress, String msg) {
		if (msg == null) {
			progressLabel.setText(Constant.messages.getString("quickstart.progress." + progress.name()));
		} else {
			progressLabel.setText(msg);
		}
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
