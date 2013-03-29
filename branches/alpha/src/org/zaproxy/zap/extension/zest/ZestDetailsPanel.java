/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 * 
 * Copyright 2013 The ZAP Development Team
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
package org.zaproxy.zap.extension.zest;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.GridBagLayout;
import java.awt.Insets;

import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.border.EtchedBorder;

import org.mozilla.zest.core.v1.ZestScript;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.AbstractPanel;
import org.zaproxy.zap.extension.tab.Tab;
import org.zaproxy.zap.view.LayoutHelper;

public class ZestDetailsPanel extends AbstractPanel implements Tab {

	private static final long serialVersionUID = 1L;
	@SuppressWarnings("unused")
	private ExtensionZest extension = null;
	private JPanel panelContent = new JPanel(new GridBagLayout());

	public ZestDetailsPanel (ExtensionZest extension) {
		super();
		this.extension = extension;
		initialize();
	}
	
	private void initialize() {
        this.setName(Constant.messages.getString("zest.details.panel.title"));
		this.setIcon(ExtensionZest.ZEST_ICON);
		this.setLayout(new BorderLayout());

		JScrollPane jScrollPane = new JScrollPane();
		jScrollPane.setFont(new java.awt.Font("Dialog", java.awt.Font.PLAIN, 11));
		jScrollPane.setHorizontalScrollBarPolicy(javax.swing.JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
		jScrollPane.setViewportView(panelContent);
		this.add(jScrollPane, BorderLayout.CENTER);
		
		showStartPage();
	}
	
	protected void showStartPage() {
		panelContent.removeAll();
		panelContent.setBackground(Color.white);
		panelContent.setBorder(BorderFactory.createEtchedBorder(EtchedBorder.RAISED));

		panelContent.add(new JLabel(Constant.messages.getString("zest.details.panel.topmsg")), 
				LayoutHelper.getGBC(0, 0, 1, 1.0D, new Insets(5,5,5,5)));

	}
	
	protected void showScriptPage(ZestScript script) {
		panelContent.removeAll();
		if (script == null) {
			panelContent.add(new JLabel(Constant.messages.getString("zest.details.panel.add.title")), 
					LayoutHelper.getGBC(0, 0, 1, 1.0D, new Insets(5,5,5,5)));
		} else {
			panelContent.add(new JLabel(Constant.messages.getString("zest.details.panel.edit.title")), 
					LayoutHelper.getGBC(0, 0, 1, 1.0D, new Insets(5,5,5,5)));
		}
		// TODO finish ;)
		
	}

}
