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

import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import org.mozilla.zest.core.v1.ZestAction;
import org.mozilla.zest.core.v1.ZestActionFail;
import org.mozilla.zest.core.v1.ZestActionPrint;
import org.mozilla.zest.core.v1.ZestActionScan;
import org.mozilla.zest.core.v1.ZestContainer;
import org.mozilla.zest.core.v1.ZestElement;
import org.mozilla.zest.core.v1.ZestRequest;
import org.mozilla.zest.core.v1.ZestScript;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionPopupMenuItem;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.httppanel.view.syntaxhighlight.HttpPanelSyntaxHighlightTextArea;
import org.zaproxy.zap.extension.script.ScriptNode;
import org.zaproxy.zap.extension.zest.ExtensionZest;
import org.zaproxy.zap.extension.zest.ZestZapUtils;

public class ZestAddActionPopupMenu extends ExtensionPopupMenuItem {

	private static final long serialVersionUID = 2282358266003940700L;

	private ExtensionZest extension;
    private List<ExtensionPopupMenuItem> subMenus = new ArrayList<>();

	/**
	 * This method initializes 
	 * 
	 */
	public ZestAddActionPopupMenu(ExtensionZest extension) {
		super("AddActionX");
		this.extension = extension;
	}
	
	/**/
    @Override
    public String getParentMenuName() {
    	return Constant.messages.getString("zest.action.add.popup");
    }
    
    @Override
    public boolean isSubMenu() {
    	return true;
    }
    @Override
    public boolean isDummyItem () {
    	return true;
    }
	    
    public boolean isEnableForComponent(Component invoker) {
    	// Remove previous submenus
    	for (ExtensionPopupMenuItem menu : subMenus) {
			View.getSingleton().getPopupMenu().removeMenu(menu);
		}
		subMenus.clear();
		if (extension.isScriptTree(invoker)) {
    		ScriptNode node = extension.getSelectedZestNode();
    		ZestElement ze = extension.getSelectedZestElement();
    		if (node == null || node.isTemplate()) {
    			return false;
    		} else if (ze != null) {
	    		if (ze instanceof ZestRequest) {
	            	reCreateSubMenu(node.getParent(), node, (ZestRequest) ZestZapUtils.getElement(node), null);
	            	return true;
	    		} else if (ze instanceof ZestContainer) {
	            	reCreateSubMenu(node, null, null, null);
	            	return true;
	    		}
    		}
    		
        } else if (invoker instanceof HttpPanelSyntaxHighlightTextArea && extension.getExtScript().getScriptUI() != null) {
			HttpPanelSyntaxHighlightTextArea panel = (HttpPanelSyntaxHighlightTextArea)invoker;
			ScriptNode node = extension.getExtScript().getScriptUI().getSelectedNode();
			
			if (node == null || node.isTemplate()) {
    			return false;
    		} else if (extension.isSelectedMessage(panel.getMessage()) &&
					panel.getSelectedText() != null && panel.getSelectedText().length() > 0) {

                if (ZestZapUtils.getElement(node) instanceof ZestRequest) {
                	reCreateSubMenu(node.getParent(), 
                			node,
                			(ZestRequest) ZestZapUtils.getElement(node), 
                			Pattern.quote(panel.getSelectedText()));
                	return true;
                }
			}
        }
       
        return false;
    }

    private void reCreateSubMenu(ScriptNode parent, ScriptNode child, ZestRequest req, String text) {
    	String type = extension.getZestTreeModel().getScriptWrapper(parent).getZestScript().getType();
    	if (ZestScript.Type.StandAlone.name().equals(type) ||
    			ZestScript.Type.Targeted.name().equals(type)) {
    		// Doenst really make sense for passive or active scripts 
    		createPopupAddActionMenu (parent, child, req, new ZestActionScan(text));
    	}
    	
		createPopupAddActionMenu (parent, child, req, new ZestActionPrint(text));
		createPopupAddActionMenu (parent, child, req, new ZestActionFail(text));
	}

    private void createPopupAddActionMenu(final ScriptNode parent, final ScriptNode child, final ZestRequest req, final ZestAction za) {
		ZestPopupMenu menu = new ZestPopupMenu(
				Constant.messages.getString("zest.action.add.popup"),
				ZestZapUtils.toUiString(za, false));
		menu.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				extension.getDialogManager().showZestActionDialog(parent, child, req, za, true);
			}});
    	menu.setMenuIndex(this.getMenuIndex());
		View.getSingleton().getPopupMenu().addMenu(menu);
		this.subMenus.add(menu);
	}

	@Override
    public boolean isSafe() {
    	return true;
    }
}
