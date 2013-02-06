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
package org.zaproxy.zap.extension.treetools;

import java.awt.Component;
import java.util.Enumeration;

import javax.swing.JTree;
import javax.swing.tree.TreeNode;
import javax.swing.tree.TreePath;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionPopupMenuItem;

public class PopupMenuTreeTools extends ExtensionPopupMenuItem {

	private static final long serialVersionUID = 1L;
	private Component invoker = null;
	/**
    
    /**
     * 
     */
    public PopupMenuTreeTools() {
        super();
 		initialize();
    }

    /**
     * @param label
     */
    public PopupMenuTreeTools(String label) {
        super(label);
    }

    /**
	 * This method initializes this
	 */
	private void initialize() {
        this.setText(Constant.messages.getString("treetools.popop"));
        
        this.addActionListener(new java.awt.event.ActionListener() { 

        	@Override
        	public void actionPerformed(java.awt.event.ActionEvent e) {        		
        		 if (invoker.getName().equals("treeSite")) {
         	        JTree tree = (JTree) invoker;
                    TreePath[] paths = tree.getSelectionPaths();
                    for (int i = 0; i < paths.length; i++) {
                    	TreePath t = paths[i];   
                    	if (tree.isExpanded(t)) {                    		
                    		expandOrCollapseFromNode(t, false);
                    	}
                    	else {
                    		expandOrCollapseFromNode(t, true);
                    	}
                    }
        		 }
        	}
        });
			
	}
	
	@SuppressWarnings("unchecked")
	private void expandOrCollapseFromNode(TreePath parent, boolean expand) {
		JTree tree = (JTree) invoker;
		TreeNode tn = (TreeNode) ((TreePath) parent).getLastPathComponent();
		
		if (tn.getChildCount() > 0) {
			for (Enumeration<TreeNode> e = tn.children(); e.hasMoreElements();) {
				  TreeNode n = (TreeNode) e.nextElement();	
				  TreePath path = parent.pathByAddingChild(n);
				  expandOrCollapseFromNode(path, expand);
			}
		}
		
		if (expand) { 
			tree.expandPath(parent);
		}
		else {
			tree.collapsePath(parent);
		}
	}
	
    @Override
    public boolean isEnableForComponent(Component invoker) {
        if (invoker instanceof JTree) {
        	this.invoker = invoker;
            JTree tree = (JTree) invoker;
            if (tree.getName().equals("treeSite")) {
				this.setEnabled(true);
                return true;
            }
        }
        return false;
    }

    @Override
    public boolean precedeWithSeparator() {
    	return true;
    }

}
