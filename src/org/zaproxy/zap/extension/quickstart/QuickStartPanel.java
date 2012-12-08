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
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.net.URL;

import javax.swing.BorderFactory;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.border.EtchedBorder;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.AbstractPanel;
import org.zaproxy.zap.extension.alert.ExtensionAlert;
import org.zaproxy.zap.extension.brk.BreakPanel;
import org.zaproxy.zap.extension.search.SearchPanel;
import org.zaproxy.zap.extension.tab.Tab;
import org.zaproxy.zap.utils.ZapTextField;
import org.zaproxy.zap.view.LayoutHelper;

public class QuickStartPanel extends AbstractPanel implements Tab {

	private static final long serialVersionUID = 1L;

	private ExtensionQuickStart extension;
	private JPanel panelContent = null;
	private JButton attackButton = null;
	private JButton stopButton = null;
	private ZapTextField urlField = null;
	private JLabel progressLabel = null;
	private JCheckBox showOnStart = null;

	public QuickStartPanel(ExtensionQuickStart extension) {
		super();
		this.extension = extension;
		initialize();
	}

	private void initialize() {
		this.setIcon(new ImageIcon(BreakPanel.class.getResource("/resource/icon/16/147.png")));	// 'lightning' icon
		this.setLayout(new BorderLayout());

		panelContent = new JPanel(new GridBagLayout());
		this.add(panelContent, BorderLayout.CENTER);
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
		panelContent.add(new JLabel(new ImageIcon(SearchPanel.class.getResource("/resource/zap128x128.png"))),
				LayoutHelper.getGBC(4, 0, 1, 0.0D, 0.0D, GridBagConstraints.NORTH));
	
		panelContent.add(new JLabel(Constant.messages.getString("quickstart.label.url")), 
				LayoutHelper.getGBC(0, 1, 1, 0.0D, new Insets(5,5,5,5)));
	
		panelContent.add(this.getUrlField(), LayoutHelper.getGBC(1, 1, 3, 0.25D));
		
		panelContent.add(this.getAttackButton(), LayoutHelper.getGBC(1, 2, 1, 0.0D));
		panelContent.add(this.getStopButton(), LayoutHelper.getGBC(2, 2, 1, 0.0D));
		panelContent.add(new JLabel(""), LayoutHelper.getGBC(3, 2, 1, 0.75D, 0.0D));	// Padding to right of buttons
		
		progressLabel = new JLabel(Constant.messages.getString("quickstart.progress." + AttackThread.Progress.notstarted.name()));
		panelContent.add(new JLabel(Constant.messages.getString("quickstart.label.progress")), 
				LayoutHelper.getGBC(0, 3, 1, 0.0D, new Insets(5,5,5,5)));
		panelContent.add(this.progressLabel, LayoutHelper.getGBC(1, 3, 3, 0.0D));

		panelContent.add(new JLabel(Constant.messages.getString("quickstart.panel.bottommsg")), 
				LayoutHelper.getGBC(0, 4, 5, 1.0D, new Insets(5,5,5,5)));
		panelContent.add(new JLabel(""), LayoutHelper.getGBC(0, 5, 4, 1.D, 1.0D));	// Padding at bottom

		panelContent.add(new JLabel(Constant.messages.getString("quickstart.label.show")), 
				LayoutHelper.getGBC(0, 6, 1, 0.0D, new Insets(5,5,5,5)));
		panelContent.add(this.getShowOnStart(), LayoutHelper.getGBC(1, 6, 1, 0.0D));

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
	
	private JCheckBox getShowOnStart() {
		if (showOnStart == null) {
			showOnStart = new JCheckBox();
			showOnStart.setSelected(true);
			showOnStart.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent e) {
					if (extension.getView().showConfirmDialog(Constant.messages.getString("quickstart.start.remove")) 
							!= JOptionPane.OK_OPTION) {
						showOnStart.setSelected(true);
						return;
					}
					extension.showOnStart(false);
				}
			});
		}
		return showOnStart;
	}
}
