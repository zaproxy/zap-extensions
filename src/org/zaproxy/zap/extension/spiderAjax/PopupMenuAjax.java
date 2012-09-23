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

import java.awt.Component;
import javax.swing.ImageIcon;
import javax.swing.JTree;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionPopupMenuItem;
import org.parosproxy.paros.model.SiteNode;

public class PopupMenuAjax extends ExtensionPopupMenuItem {

	private static final long serialVersionUID = 1L;
	private ExtensionAjax extension = null;
	private JTree treeSite = null;


	/**
	 * 
	 * @param extension
	 */
	public PopupMenuAjax(ExtensionAjax extension) {
		super();
		this.extension=extension;
		initialize();
	}

	/**
	 * @param label
	 */
	public PopupMenuAjax(String label,ExtensionAjax extension) {
		super(label);
		this.extension=extension;

	}

	/**
	 * @return if its a submenu
	 */
	@Override
	public boolean isSubMenu() {
		return true;
	}

	/**
	 * @return the parent menu name
	 */
	@Override
	public String getParentMenuName() {
		return Constant.messages.getString("attack.site.popup");
	}

	/**
	 * @return the parent index
	 */
	@Override
	public int getParentMenuIndex() {
		return ATTACK_MENU_INDEX;
	}

	/**
	 * This method initializes this
	 * 
	 */
	private void initialize() {
		 this.setText(this.extension.getString("ajax.site.popup"));
	        this.setIcon(new ImageIcon(getClass().getResource("/resource/icon/16/spiderAjax.png")));

	        this.addActionListener(new java.awt.event.ActionListener() { 

	        	@Override
	        	public void actionPerformed(java.awt.event.ActionEvent e) {    
	        		if (treeSite != null) {
	        		    SiteNode node = (SiteNode) treeSite.getLastSelectedPathComponent();
	        		    if (node != null) {
	        		    	extension.spiderSite(node, true);
	        		    }
	        		}
	        	}
	        });

	}
	
	/**
	 * 
	 * @return if component enabled
	 */
	@Override
	public boolean isEnableForComponent(Component invoker) {
		
		treeSite = getTree(invoker);
		if (treeSite != null) {
			SiteNode node = (SiteNode) treeSite.getLastSelectedPathComponent();
			if (node != null && !node.isRoot()) {
				this.setEnabled(true);
			} else {
				this.setEnabled(false);
			}
			return true;
		}
		return false;
	}

	/**
	 * 
	 * @param invoker
	 * @return
	 */
	private JTree getTree(Component invoker) {
		if (invoker instanceof JTree) {
			JTree tree = (JTree) invoker;
			if (tree.getName().equals("treeSite")) {
				return tree;
			}
		}

		return null;
	}

	/**
	 * Sets the extension object
	 * @param extension
	 */
	void setExtension(ExtensionAjax extension) {
		this.extension = extension;
	}

}

