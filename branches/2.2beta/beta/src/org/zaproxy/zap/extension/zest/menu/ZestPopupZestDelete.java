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

import javax.swing.JTree;

import org.mozilla.zest.core.v1.ZestScript;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionPopupMenuItem;
import org.zaproxy.zap.extension.script.ScriptNode;
import org.zaproxy.zap.extension.zest.ExtensionZest;
import org.zaproxy.zap.extension.zest.ZestZapUtils;


/**
 * ZAP: New Popup Menu Alert Delete
 */
public class ZestPopupZestDelete extends ExtensionPopupMenuItem {

	private static final long serialVersionUID = 1L;

	private ExtensionZest extension = null;

    /**
     * 
     */
    public ZestPopupZestDelete(ExtensionZest extension) {
        super();
        this.extension = extension;
 		initialize();
    }

    /**
     * @param label
     */
    public ZestPopupZestDelete(String label) {
        super(label);
    }

	/**
	 * This method initializes this
	 */
	private void initialize() {
        this.setText(Constant.messages.getString("zest.delete.popup"));

        this.addActionListener(new java.awt.event.ActionListener() { 

        	@Override
        	public void actionPerformed(java.awt.event.ActionEvent e) {
            	for (ScriptNode node : extension.getSelectedZestNodes()) {
		    		deleteNode(node);
			    }
        	}
        });
			
	}
	
	private void deleteNode(ScriptNode node) {
		while (node.getChildCount() > 0) {
			deleteNode((ScriptNode)node.getChildAt(0));
		}
    	extension.delete(node);
	}
	
    @Override
    public boolean isEnableForComponent(Component invoker) {
		if (extension.isScriptTree(invoker)) {
            try {
                JTree tree = (JTree) invoker;
                if (tree.getLastSelectedPathComponent() != null) {
                    ScriptNode node = (ScriptNode) tree.getLastSelectedPathComponent();
                    // Cant delete root, and children of root are scripts - have to close these...
                    // TODO ^ these checks
                    return ZestZapUtils.isZestNode(node) &&
                    		! (ZestZapUtils.getElement(node) instanceof ZestScript) &&
                    		 ZestZapUtils.getShadowLevel(node)==0;
                    /*
                    return (node != null && ! node.isRoot() && ! node.getParent().isRoot()
                    		&& ! node.isShadow() && 
                    		! ZestTreeElement.isSubclass(node.getZestElement(), ZestTreeElement.Type.COMMON_TESTS));
                    		*/
                }
            } catch (Exception e) {}
            
        }
        return false;
    }
}
