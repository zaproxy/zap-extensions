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
package org.zaproxy.zap.extension.httpsInfo;

import java.awt.Component;

import javax.swing.JTree;

import org.parosproxy.paros.extension.ExtensionPopupMenuItem;
import org.parosproxy.paros.model.SiteNode;

/*
 * An example ZAP extension which adds a right click menu item to all of the main
 * tabs which list messages. 
 * 
 * This class is defines the popup menu item.
 */
public class MenuEntry extends ExtensionPopupMenuItem {

	private static final long serialVersionUID = 1L;
	private final RightClickMenu extension;
	private SiteNode node = null;

	public MenuEntry(String label, RightClickMenu extension) {
		super(label);
		this.extension = extension;
		init();
	}

	public void init() {
		this.addActionListener(new java.awt.event.ActionListener() {

			@Override
			public void actionPerformed(java.awt.event.ActionEvent e) {
				extension.showSslTlsInfo(getHostName(node.getNodeName()));
			}
		});
	}

	@Override
	public boolean isEnableForComponent(Component invoker) {
		if (invoker instanceof JTree) {
			JTree tree = (JTree) invoker;
			if (tree.getLastSelectedPathComponent() instanceof SiteNode) {
				node = (SiteNode) tree.getLastSelectedPathComponent();
				if (node.getNodeName().startsWith("https://")) {
					this.setEnabled(true);
					return true;
				}
			}
		}
		return false;
	}

	public String getHostName(String name) {
		String host = name;
		host = host.substring(8);
		while (!Character.isDigit(host.charAt(host.length() - 1))
				&& !Character.isLetter(host.charAt(host.length() - 1))) {
			host = host.substring(0, host.length() - 1);
		}
		return host;
	}
}