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
import java.util.LinkedList;
import java.util.List;
import java.util.regex.Pattern;

import org.mozilla.zest.core.v1.ZestConditional;
import org.mozilla.zest.core.v1.ZestContainer;
import org.mozilla.zest.core.v1.ZestElement;
import org.mozilla.zest.core.v1.ZestExpression;
import org.mozilla.zest.core.v1.ZestExpressionRegex;
import org.mozilla.zest.core.v1.ZestExpressionResponseTime;
import org.mozilla.zest.core.v1.ZestExpressionStatusCode;
import org.mozilla.zest.core.v1.ZestExpressionURL;
import org.mozilla.zest.core.v1.ZestRequest;
import org.mozilla.zest.core.v1.ZestResponse;
import org.mozilla.zest.core.v1.ZestStatement;
import org.mozilla.zest.core.v1.ZestStructuredExpression;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionPopupMenuItem;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.httppanel.view.syntaxhighlight.HttpPanelSyntaxHighlightTextArea;
import org.zaproxy.zap.extension.script.ScriptNode;
import org.zaproxy.zap.extension.zest.ExtensionZest;
import org.zaproxy.zap.extension.zest.ZestZapUtils;

public class ZestAddConditionPopupMenu extends ExtensionPopupMenuItem {

	private static final long serialVersionUID = 2282358266003940700L;

	private ExtensionZest extension;
    private List<ExtensionPopupMenuItem> subMenus = new ArrayList<>();

	//private static final Logger logger = Logger.getLogger(ZestAddConditionPopupMenu.class);

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
		if (extension.isScriptTree(invoker)) {
    		ScriptNode node = extension.getSelectedZestNode();
    		ZestElement ze = extension.getSelectedZestElement();

            if (node != null) {
                if (ze instanceof ZestRequest) {
                	reCreateSubMenu(node.getParent(), node, (ZestRequest) ze, "BODY", "");
                	return true;
                } else if (ze instanceof ZestContainer /*&& TODO
                		! ZestTreeElement.isSubclass(node.getParent().getZestElement(), ZestTreeElement.Type.PASSIVE_SCRIPT)*/) {
                	reCreateSubMenu(node, null, null, "BODY", "");
                	return true;
                	/* TODO
                } else if (ZestTreeElement.Type.COMMON_TESTS.equals(node.getTreeType())) {
                	reCreateSubMenu(node, null, "BODY", "");
                	return true;
                	*/
                }
            }
        } else if (invoker instanceof HttpPanelSyntaxHighlightTextArea && extension.getExtScript().getScriptUI() != null) {
			HttpPanelSyntaxHighlightTextArea panel = (HttpPanelSyntaxHighlightTextArea)invoker;
    		ScriptNode node = extension.getSelectedZestNode();
    		ZestElement ze = extension.getSelectedZestElement();

			if (node != null && extension.isSelectedZestOriginalResponseMessage(panel.getMessage()) &&
					panel.getSelectedText() != null && panel.getSelectedText().length() > 0) {
                if (ze instanceof ZestRequest) {
                	ZestRequest req = (ZestRequest) ze;
                	String loc = "BODY";
                	if (req.getResponse() != null && req.getResponse().getHeaders() != null &&
                			req.getResponse().getHeaders().indexOf(panel.getSelectedText()) >= 0) {
                		loc = "HEAD";
                	}
                	
                	reCreateSubMenu(node.getParent(),
                			node,
                			(ZestRequest) ze, 
                			loc,
                			Pattern.quote(panel.getSelectedText()));
                	return true;
                }
			}
        }
        return false;
    }

    protected void reCreateSubMenu(ScriptNode parent, ScriptNode child, ZestStatement stmt, String loc, String text) {
		createPopupAddActionMenu (parent, child, stmt, new ZestConditional(new ZestExpressionRegex(loc, text)));
		createPopupAddActionMenu (parent, child, stmt, new ZestConditional(new ZestExpressionStatusCode()));
		createPopupAddActionMenu (parent, child, stmt, new ZestConditional(new ZestExpressionResponseTime()));
		createPopupAddActionMenu (parent, child, stmt, new ZestConditional(new ZestExpressionURL()));
		createPopupAddActionMenu(parent, child, stmt, new ZestConditional());
	}

    private void createPopupAddActionMenu(final ScriptNode parent, ScriptNode child, 
    		final ZestStatement stmt, final ZestConditional za) {
    	 final List<ScriptNode> nodes=new LinkedList<>();
    	nodes.add(child);
		ZestPopupMenu menu = new ZestPopupMenu(
				Constant.messages.getString("zest.condition.add.popup"),
				ZestZapUtils.toUiString(za, false));
		menu.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				extension.getDialogManager().showZestConditionalDialog(parent, nodes, stmt, za, true, false);
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
