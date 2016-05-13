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
package org.zaproxy.zap.extension.requester;

import java.awt.GridBagConstraints;
import javax.swing.Icon;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;

import org.parosproxy.paros.Constant;

public class CloseTabPanel extends JPanel {	
	
	private static final long serialVersionUID = 1L;
	private static final Icon CLOSE_TAB_GREY_ICON = new ImageIcon(
			CloseTabPanel.class.getResource("/resource/icon/fugue/cross-small-grey.png"));
	private static final Icon CLOSE_TAB_RED_ICON = new ImageIcon(
			CloseTabPanel.class.getResource("/resource/icon/fugue/cross-small-red.png"));
	
	private NumberedTabbedPane ntp;	

	public CloseTabPanel(String tabName, NumberedTabbedPane ntp) {
		super();
		this.ntp = ntp;
    	this.setOpaque(false);
    	JLabel lblTitle = new JLabel(tabName);
    	JButton btnClose = new JButton();
    	btnClose.setOpaque(false);
    	
		// Configure icon and rollover icon for button
		btnClose.setRolloverIcon(CLOSE_TAB_RED_ICON);
		btnClose.setRolloverEnabled(true);
		btnClose.setContentAreaFilled(false);
		btnClose.setToolTipText(Constant.messages.getString("all.button.close"));
		btnClose.setIcon(CLOSE_TAB_GREY_ICON);
		// Set a border only on the left side so the button doesn't make the tab too big
		btnClose.setBorder(new EmptyBorder(0, 6, 0, 0));
		// This is needed to Macs for some reason
		btnClose.setBorderPainted(false);

		// Make sure the button can't get focus, otherwise it looks funny
		btnClose.setFocusable(false);
    	GridBagConstraints gbc = new GridBagConstraints();
    	gbc.gridx = 0;
    	gbc.gridy = 0;
    	gbc.weightx = 1;

    	this.add(lblTitle, gbc);

    	gbc.gridx++;
    	gbc.weightx = 0;
    	this.add(btnClose, gbc);    	

    	btnClose.addActionListener(new CloseActionHandler(this.ntp, tabName));    	
    	
    }

}
