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
import java.util.ArrayList;
import java.util.List;

import javax.swing.JTree;
import javax.swing.tree.TreePath;

import org.apache.log4j.Logger;
import org.mozilla.zest.core.v1.ZestStatement;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionPopupMenuItem;


/**
 * ZAP: New Popup Menu Alert Delete
 */
public class ZestPopupNodeCopyOrCut extends ExtensionPopupMenuItem {

	private static final long serialVersionUID = 1L;

	private static final Logger logger = Logger.getLogger(ZestPopupNodeCopyOrCut.class);

	private ExtensionZest extension = null;
	private boolean cut;

    /**
     * 
     */
    public ZestPopupNodeCopyOrCut(ExtensionZest extension, boolean cut) {
        super();
        this.extension = extension;
        this.cut = cut;
 		initialize();
    }

    /**
     * @param label
     */
    public ZestPopupNodeCopyOrCut(String label) {
        super(label);
    }

	/**
	 * This method initializes this
	 */
	private void initialize() {
		if (cut) {
			this.setText(Constant.messages.getString("zest.cnp.cut.popup"));
		} else {
			this.setText(Constant.messages.getString("zest.cnp.copy.popup"));
		}

        this.addActionListener(new java.awt.event.ActionListener() { 
        	@Override
        	public void actionPerformed(java.awt.event.ActionEvent e) {
			    TreePath[] paths = extension.getZestScriptsPanel().getTree().getSelectionPaths();
			    List<ZestNode> nodes = new ArrayList<ZestNode>();
			    if (paths != null) {
			    	for (TreePath path : paths) {
			    		ZestNode node = (ZestNode)path.getLastPathComponent();
			    		if (node.getZestElement() instanceof ZestStatement) {
			    			nodes.add((ZestNode)path.getLastPathComponent());
			    		}
			    	}
			    	extension.setCnpNodes(nodes);
			    	extension.setCut(cut);
			    }
        	}
        });
			
	}
	
    @Override
    public boolean isEnableForComponent(Component invoker) {
        if (invoker.getName() != null && invoker.getName().equals("ZestTree")) {
            try {
                JTree tree = (JTree) invoker;
                if (tree.getLastSelectedPathComponent() != null) {
                	/*
                	if (tree.getSelectionPaths().length != 1) {
                		// Start by just supporting one at a time..
                		return false;
                	}
                	* /
                    ZestNode node = (ZestNode) tree.getLastSelectedPathComponent();
            		this.setEnabled(false);
            		
            		TreePath[] paths = tree.getSelectionPaths();
            		
                    if (node == null || node.isRoot()) {
                    	return false;
                    } else if (node.isShadow()) {
                    	// Cant copy these
                    } else if (! (node.getZestElement() instanceof ZestStatement)) {
                    	// Cant copy these
                    } else {
               			this.setEnabled(true);
                    }
                    */
    			    TreePath[] paths = extension.getZestScriptsPanel().getTree().getSelectionPaths();
           			this.setEnabled(false);
    			    if (paths != null) {
    			    	for (TreePath path : paths) {
    			    		ZestNode node = (ZestNode)path.getLastPathComponent();
    	                    if (node == null || node.isRoot()) {
    	               			this.setEnabled(false);
    	                    	return false;
    	                    } else if (node.isShadow()) {
    	                    	// Ignore these
    	                    } else if (! (node.getZestElement() instanceof ZestStatement)) {
    	                    	// Cant copy these
    	               			this.setEnabled(false);
    	               			break;
    	                    } else {
    	               			this.setEnabled(true);
    	                    }
    			    	}
    			    }
                    
                    return true;
                }
            } catch (Exception e) {
            	logger.error(e.getMessage(), e);
            }
            
        }
        return false;
    }
}
