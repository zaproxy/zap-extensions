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
package org.zaproxy.zap.extension.zest.menu;

import java.util.ArrayList;
import java.util.List;

import javax.swing.JMenuItem;

import org.mozilla.zest.core.v1.ZestConditional;
import org.mozilla.zest.core.v1.ZestElement;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionPopupMenuItem;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.authentication.ScriptBasedAuthenticationMethodType;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptNode;
import org.zaproxy.zap.extension.zest.ExtensionZest;
import org.zaproxy.zap.view.messagecontainer.http.HttpMessageContainer;
import org.zaproxy.zap.view.popup.PopupMenuItemHistoryReferenceContainer;

public class ZestAddToScriptPopupMenu extends PopupMenuItemHistoryReferenceContainer {

	private static final long serialVersionUID = 2282358266003940700L;

	private ExtensionZest extension;
    private List<ExtensionPopupMenuItem> subMenus = new ArrayList<>();

	/**
	 * This method initializes 
	 * 
	 */
	public ZestAddToScriptPopupMenu(ExtensionZest extension) {
		super("AddToZestX", true);
		this.extension = extension;
	}
	
	/**/
    @Override
    public String getParentMenuName() {
    	return Constant.messages.getString("zest.addto.popup", true);
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
    public void performHistoryReferenceActions (List<HistoryReference> hrefs) {
	}

	@Override
	public boolean isEnableForInvoker(Invoker invoker, HttpMessageContainer httpMessageContainer) {
		reCreateSubMenu();
		return true;
	}

    private void reCreateSubMenu() {
    	final List<JMenuItem> mainPopupMenuItems = View.getSingleton().getPopupList();
    	for (ExtensionPopupMenuItem menu : subMenus) {
			mainPopupMenuItems.remove(menu);
			
		}
		subMenus.clear();
		ScriptNode selNode = extension.getSelectedZestNode();
		ZestElement ze = extension.getSelectedZestElement();
		
		if (ze != null) {
			if (ze instanceof ZestConditional) {
	        	ExtensionPopupMenuItem piicm = createPopupAddToScriptMenu(selNode);
	        	piicm.setMenuIndex(this.getMenuIndex());
				mainPopupMenuItems.add(piicm);
				this.subMenus.add(piicm);
			}
		}
		
		for (ScriptNode node : extension.getZestScriptNodes(ExtensionScript.TYPE_STANDALONE)) {
        	ExtensionPopupMenuItem piicm = createPopupAddToScriptMenu(node);
        	piicm.setMenuIndex(this.getMenuIndex());
			mainPopupMenuItems.add(piicm);
			this.subMenus.add(piicm);
		}
		// TODO handle auth scripts... is there a better way to do this??
		for (ScriptNode node : extension.getZestScriptNodes(ScriptBasedAuthenticationMethodType.SCRIPT_TYPE_AUTH)) {
        	ExtensionPopupMenuItem piicm = createPopupAddToScriptMenu(node);
        	piicm.setMenuIndex(this.getMenuIndex());
			mainPopupMenuItems.add(piicm);
			this.subMenus.add(piicm);
		}
		
		// TODO Sequence - makes it possible to add requests to a sequence script 
		for (ScriptNode node : extension.getZestScriptNodes("sequence")) {
			ExtensionPopupMenuItem piicm = createPopupAddToScriptMenu(node);
			piicm.setMenuIndex(this.getMenuIndex());
			mainPopupMenuItems.add(piicm);
			this.subMenus.add(piicm);
		}
		
        // Add the 'new zest' menu
        ExtensionPopupMenuItem piicm = createPopupAddToScriptMenu();
		mainPopupMenuItems.add(piicm);
		this.subMenus.add(piicm);
	}

    private ExtensionPopupMenuItem createPopupAddToScriptMenu() {
    	return new ZestAddToScriptMenu(extension);
	}

    private ExtensionPopupMenuItem createPopupAddToScriptMenu(ScriptNode node) {
    	return new ZestAddToScriptMenu(extension, node);
	}

	@Override
    public boolean isSafe() {
    	return true;
    }

	@Override
	public void performAction(HistoryReference href) {
		// Do nothing
	}
}
