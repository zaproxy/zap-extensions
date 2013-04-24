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
import java.util.regex.Pattern;

import javax.swing.JTree;

import org.apache.log4j.Logger;
import org.mozilla.zest.core.v1.ZestConditionRegex;
import org.mozilla.zest.core.v1.ZestConditionResponseTime;
import org.mozilla.zest.core.v1.ZestConditionStatusCode;
import org.mozilla.zest.core.v1.ZestConditionURL;
import org.mozilla.zest.core.v1.ZestConditional;
import org.mozilla.zest.core.v1.ZestContainer;
import org.mozilla.zest.core.v1.ZestRequest;
import org.mozilla.zest.core.v1.ZestStatement;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionPopupMenuItem;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.httppanel.view.syntaxhighlight.HttpPanelSyntaxHighlightTextArea;

public class ZestAddConditionPopupMenu extends ExtensionPopupMenuItem {

	private static final long serialVersionUID = 2282358266003940700L;

	private ExtensionZest extension;
    private List<ExtensionPopupMenuItem> subMenus = new ArrayList<>();

	private static final Logger logger = Logger.getLogger(ZestAddConditionPopupMenu.class);

	/**
	 * This method initializes 
	 * 
	 */
	public ZestAddConditionPopupMenu(ExtensionZest extension) {
		super("AddConditionX");
		this.extension = extension;
	}
	
	/**/
    @Override
    public String getParentMenuName() {
    	return Constant.messages.getString("zest.condition.add.popup");
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
                    if (node != null) {
	                    if (node.getZestElement() instanceof ZestRequest) {
	                    	reCreateSubMenu(node.getParent(), (ZestRequest) node.getZestElement(), "BODY", "");
	                    	return true;
	                    } else if (node.getZestElement() instanceof ZestContainer &&
	                    		! ZestTreeElement.isSubclass(node.getParent().getZestElement(), ZestTreeElement.Type.PASSIVE_SCRIPT)) {
	                    	reCreateSubMenu(node, null, "BODY", "");
	                    	return true;
	                    } else if (ZestTreeElement.Type.COMMON_TESTS.equals(node.getTreeType())) {
	                    	reCreateSubMenu(node, null, "BODY", "");
	                    	return true;
	                    }
                    }
                }
            } catch (Exception e) {
            	logger.error(e.getMessage(), e);
            }
        } else if (invoker instanceof HttpPanelSyntaxHighlightTextArea) {
			HttpPanelSyntaxHighlightTextArea panel = (HttpPanelSyntaxHighlightTextArea)invoker;
			ZestNode node = extension.getSelectedScriptsNode();
			
			if (node != null && extension.isSelectedZestOriginalResponseMessage(panel.getMessage()) &&
					panel.getSelectedText() != null && panel.getSelectedText().length() > 0) {
                if (node.getZestElement() instanceof ZestRequest) {
                	ZestRequest req = (ZestRequest) node.getZestElement();
                	String loc = "BODY";
                	if (req.getResponse() != null && req.getResponse().getHeaders() != null &&
                			req.getResponse().getHeaders().indexOf(panel.getSelectedText()) >= 0) {
                		loc = "HEAD";
                	}
                	
                	reCreateSubMenu(node.getParent(), 
                			(ZestRequest) node.getZestElement(), 
                			loc,
                			Pattern.quote(panel.getSelectedText()));
                	return true;
                }
			}
        }
        return false;
    }

    private void reCreateSubMenu(ZestNode script, ZestStatement stmt, String loc, String text) {
		createPopupAddActionMenu (script, stmt, new ZestConditionRegex(loc, text));
		createPopupAddActionMenu (script, stmt, new ZestConditionStatusCode());
		createPopupAddActionMenu (script, stmt, new ZestConditionResponseTime());
		createPopupAddActionMenu (script, stmt, new ZestConditionURL());
	}

    private void createPopupAddActionMenu(final ZestNode parent, final ZestStatement stmt, final ZestConditional za) {
    	
		ZestAddConditionMenu menu = new ZestAddConditionMenu(za);
		menu.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				extension.getZestScriptsPanel().showZestConditionalDialog(parent, stmt, za, true);
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
