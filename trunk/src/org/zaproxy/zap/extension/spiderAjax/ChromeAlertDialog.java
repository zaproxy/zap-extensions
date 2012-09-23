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
package org.zaproxy.zap.extension.spiderAjax;

import java.awt.Frame;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.HeadlessException;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import org.parosproxy.paros.extension.AbstractDialog;

/**
 * This class is used to show an alert to users who do not have
 * installed in their system the chrome driver when they try to
 * run the spider ajax with chrome.
 *
 */
public class ChromeAlertDialog extends AbstractDialog {

	private static final long serialVersionUID = 1L;
	private JPanel jPanel = null;
	private JButton btnCancel = null;
	private ExtensionAjax extension;

	/**
	 * @throws HeadlessException
	 */
	public ChromeAlertDialog(ExtensionAjax e) throws HeadlessException {
		super();
		this.extension = e;
		initialize();
	}

	/**
	 * @param arg0
	 * @param arg1
	 * @throws HeadlessException
	 */
	public ChromeAlertDialog(Frame arg0, boolean arg1, ExtensionAjax e)
			throws HeadlessException {
		super(arg0, arg1);
		this.extension = e;
		initialize();
	}

	/**
	 * This method initializes this
	 * 
	 */
	private void initialize() {
		this.setTitle(this.extension.getString("ajax.chrome.alert.title"));
		this.setContentPane(getJPanel());
		this.setSize(407, 255);
		this.addWindowListener(new java.awt.event.WindowAdapter() {
			@Override
			public void windowOpened(java.awt.event.WindowEvent e) {
			}

			@Override
			public void windowClosing(java.awt.event.WindowEvent e) {
				btnCancel.doClick();
			}
		});

		pack();
	}

	/**
	 * This method initializes jPanel
	 * 
	 * @return javax.swing.JPanel
	 */
	private JPanel getJPanel() {
		if (jPanel == null) {
			java.awt.GridBagConstraints gridBagConstraints13 = new GridBagConstraints();

			javax.swing.JLabel jLabel = new JLabel();
			jLabel.setText(this.extension.getString("ajax.chrome.alert.msg"));
			java.awt.GridBagConstraints gridBagConstraints3 = new GridBagConstraints();

			java.awt.GridBagConstraints gridBagConstraints2 = new GridBagConstraints();

			jPanel = new JPanel();
			jPanel.setLayout(new GridBagLayout());
			jPanel.setPreferredSize(new java.awt.Dimension(700, 70));
			jPanel.setMinimumSize(new java.awt.Dimension(550, 70));
			gridBagConstraints2.gridx = 1;
			gridBagConstraints2.gridy = 5;
			gridBagConstraints2.insets = new java.awt.Insets(2, 2, 2, 2);
			gridBagConstraints2.anchor = java.awt.GridBagConstraints.EAST;
			gridBagConstraints3.gridx = 2;
			gridBagConstraints3.gridy = 5;
			gridBagConstraints3.insets = new java.awt.Insets(2, 2, 2, 10);
			gridBagConstraints3.anchor = java.awt.GridBagConstraints.EAST;

			gridBagConstraints13.gridx = 0;
			gridBagConstraints13.gridy = 5;
			gridBagConstraints13.fill = java.awt.GridBagConstraints.HORIZONTAL;
			gridBagConstraints13.weightx = 1.0D;
			gridBagConstraints13.insets = new java.awt.Insets(2, 10, 2, 5);

			// jPanel.add(getJScrollPane(), gridBagConstraints15);
			jPanel.add(jLabel, gridBagConstraints13);
			jPanel.add(getBtnCancel(), gridBagConstraints2);
		}
		return jPanel;
	}

	/**
	 * This method initializes the cancel button
	 * 
	 * @return javax.swing.JButton
	 */
	private JButton getBtnCancel() {
		if (btnCancel == null) {
			btnCancel = new JButton();
			btnCancel.setText(this.extension.getString("ajax.chrome.alert.button"));
			btnCancel.setMaximumSize(new java.awt.Dimension(100, 40));
			btnCancel.setMinimumSize(new java.awt.Dimension(100, 30));
			btnCancel.setPreferredSize(new java.awt.Dimension(120, 30));
			btnCancel.setEnabled(true);
			btnCancel.addActionListener(new java.awt.event.ActionListener() {

				@Override
				public void actionPerformed(java.awt.event.ActionEvent e) {
					ChromeAlertDialog.this.setVisible(false);
				}
			});

		}
		return btnCancel;
	}
}
