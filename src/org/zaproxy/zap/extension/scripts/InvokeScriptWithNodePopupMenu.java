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
package org.zaproxy.zap.extension.scripts;

import java.util.ArrayList;
import java.util.List;

import javax.swing.JMenuItem;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionPopupMenuItem;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.view.popup.PopupMenuItemSiteNodeContainer;

public class InvokeScriptWithNodePopupMenu extends PopupMenuItemSiteNodeContainer {

	private static final long serialVersionUID = 2282358266003940700L;

	private ExtensionScriptsUI extension;
    private List<ExtensionPopupMenuItem> subMenus = new ArrayList<>();

	/**
	 * This method initializes 
	 * 
	 */
	public InvokeScriptWithNodePopupMenu(ExtensionScriptsUI extension) {
		super("ScriptsInvokeX", true);
		this.extension = extension;
	}
	
	/**/
    @Override
    public String getParentMenuName() {
    	return Constant.messages.getString("scripts.runscript.popup");
    }
    
    @Override
    public boolean isSubMenu() {
    	return true;
    }
    @Override
    public boolean isDummyItem () {
    	return true;
    }
	    
	@Override
	public void performAction(SiteNode sn) {
		// Do nothing
	}

	@Override
    public boolean isButtonEnabledForSiteNode (SiteNode sn) {
		reCreateSubMenu();
		
    	return false;
    }
	
    private void reCreateSubMenu() {
    	final List<JMenuItem> mainPopupMenuItems = View.getSingleton().getPopupList();
    	for (ExtensionPopupMenuItem menu : subMenus) {
			mainPopupMenuItems.remove(menu);
			
		}
		subMenus.clear();
		
		for (ScriptWrapper script : extension.getExtScript().getScripts(ExtensionScript.TYPE_TARGETED)) {
        	ExtensionPopupMenuItem piicm = createPopupAddToScriptMenu(script);
        	piicm.setMenuIndex(this.getMenuIndex());
			mainPopupMenuItems.add(piicm);
			this.subMenus.add(piicm);
		}
	}

    private ExtensionPopupMenuItem createPopupAddToScriptMenu(ScriptWrapper script) {
    	return new InvokeScriptWithNodeMenu(extension, script);
	}

	@Override
    public boolean isSafe() {
    	return true;
    }
}
