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

import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JTree;

import org.mozilla.zest.core.v1.ZestRequest;
import org.mozilla.zest.core.v1.ZestScript;
import org.mozilla.zest.core.v1.ZestTransformFieldReplace;
import org.mozilla.zest.core.v1.ZestTransformRndIntReplace;
import org.mozilla.zest.core.v1.ZestTransformation;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionPopupMenuItem;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.httppanel.view.syntaxhighlight.HttpPanelSyntaxHighlightTextArea;

public class ZestAddTransformationPopupMenu extends ExtensionPopupMenuItem {

	private static final long serialVersionUID = 2282358266003940700L;

	private ExtensionZest extension;
    private List<ExtensionPopupMenuItem> subMenus = new ArrayList<>();

	/**
	 * This method initializes 
	 * 
	 */
	public ZestAddTransformationPopupMenu(ExtensionZest extension) {
		super("AddTestX");
		this.extension = extension;
	}
	
	/**/
    @Override
    public String getParentMenuName() {
    	return Constant.messages.getString("zest.transformation.add.popup");
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
        if (invoker.getName() != null && invoker.getName().equals("ZestTree")) {
            try {
                JTree tree = (JTree) invoker;
                if (tree.getLastSelectedPathComponent() != null) {
                    ZestNode node = (ZestNode) tree.getLastSelectedPathComponent();
                    if (node != null && node.getZestElement() instanceof ZestRequest) {
                    	
                    	reCreateSubMenu(extension.getScriptWrapper(node), node, null);
                    	return true;
                    }
                }
            } catch (Exception e) {}
        } else if (invoker instanceof HttpPanelSyntaxHighlightTextArea) {
			HttpPanelSyntaxHighlightTextArea panel = (HttpPanelSyntaxHighlightTextArea)invoker;
			ZestNode node = extension.getSelectedScriptsNode();
			
			if (node != null && extension.isSelectedZestOriginalRequestMessage(panel.getMessage()) &&
					panel.getSelectedText() != null && panel.getSelectedText().length() > 0) {

				reCreateSubMenu((ZestScript) ((ZestNode)node.getParent()).getZestElement(), 
            			node, panel.getSelectedText());
            	return true;
			}
        }
        return false;
    }

    private void reCreateSubMenu(ZestScript script, ZestNode req, String text) {
		createPopupAddTransformationMenu (script, req, new ZestTransformFieldReplace(text));
		createPopupAddTransformationMenu (script, req, new ZestTransformRndIntReplace(text));
	}

    private void createPopupAddTransformationMenu(final ZestScript script, 
    		final ZestNode req, final ZestTransformation za) {
		ZestAddTransformationMenu menu = new ZestAddTransformationMenu(za);
		menu.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				extension.getZestScriptsPanel().showZestTransformationDialog(script, req, za, true);
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
