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

import org.mozilla.zest.core.v1.ZestAssertBodyRegex;
import org.mozilla.zest.core.v1.ZestAssertHeaderRegex;
import org.mozilla.zest.core.v1.ZestAssertLength;
import org.mozilla.zest.core.v1.ZestAssertStatusCode;
import org.mozilla.zest.core.v1.ZestAssertion;
import org.mozilla.zest.core.v1.ZestRequest;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionPopupMenuItem;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.httppanel.view.syntaxhighlight.HttpPanelSyntaxHighlightTextArea;

public class ZestAddAssertionPopupMenu extends ExtensionPopupMenuItem {

	private static final long serialVersionUID = 2282358266003940700L;

	private ExtensionZest extension;
    private List<ExtensionPopupMenuItem> subMenus = new ArrayList<>();

	/**
	 * This method initializes 
	 * 
	 */
	public ZestAddAssertionPopupMenu(ExtensionZest extension) {
		super("AddAssertX");
		this.extension = extension;
	}
	
	/**/
    @Override
    public String getParentMenuName() {
    	return Constant.messages.getString("zest.assert.add.popup");
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
                    	reCreateSubMenu((ZestRequest) node.getZestElement(), null);
                    	return true;
                    }
                }
            } catch (Exception e) {}
        } else if (invoker instanceof HttpPanelSyntaxHighlightTextArea) {
			HttpPanelSyntaxHighlightTextArea panel = (HttpPanelSyntaxHighlightTextArea)invoker;
			ZestNode node = extension.getSelectedScriptsNode();
			
			if (node != null && extension.isSelectedZestOriginalResponseMessage(panel.getMessage()) &&
					panel.getSelectedText() != null && panel.getSelectedText().length() > 0) {

                if (node.getZestElement() instanceof ZestRequest) {
                	reCreateSubMenu((ZestRequest) node.getZestElement(), Pattern.quote(panel.getSelectedText()));
                	return true;
                }
			}
        }
        return false;
    }

    private void reCreateSubMenu(ZestRequest req, String text) {
		boolean incStatusCode = true;
		boolean incLength = true;
		for (ZestAssertion za : req.getAssertions()) {
			if (za instanceof ZestAssertStatusCode) {
				incStatusCode = false;
			} else if (za instanceof ZestAssertLength) {
				incLength = false;
			}
		}
		// Only makes sence to have one of each of these
		if (incStatusCode) {
			createPopupAddAssertionMenu (req, new ZestAssertStatusCode());
		}
		if (incLength) {
			createPopupAddAssertionMenu (req, new ZestAssertLength());
		}
		// Can be any number of these
		createPopupAddAssertionMenu (req, new ZestAssertHeaderRegex(text));
		createPopupAddAssertionMenu (req, new ZestAssertBodyRegex(text));
	}

    private void createPopupAddAssertionMenu(final ZestRequest req, final ZestAssertion za) {
		ZestAddAssertionMenu menu = new ZestAddAssertionMenu(za);
		menu.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				extension.getZestScriptsPanel().showZestAssertionDialog(req, za, true);
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
