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

import java.awt.Component;

import javax.swing.JTree;
import javax.swing.tree.TreePath;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionPopupMenuItem;
import org.zaproxy.zap.extension.script.ScriptNode;
import org.zaproxy.zap.extension.script.ScriptWrapper;


/**
 * ZAP: New Popup Menu Alert Delete
 */
public class PopupEnableDisableScript extends ExtensionPopupMenuItem {

	private static final long serialVersionUID = 1L;

	private static final Logger logger = Logger.getLogger(PopupEnableDisableScript.class);

	private ExtensionScripts extension = null;

    /**
     * 
     */
    public PopupEnableDisableScript(ExtensionScripts extension) {
        super();
        this.extension = extension;
 		initialize();
    }

    /**
     * @param label
     */
    public PopupEnableDisableScript(String label) {
        super(label);
    }

	/**
	 * This method initializes this
	 */
	private void initialize() {

        this.addActionListener(new java.awt.event.ActionListener() { 
        	@Override
        	public void actionPerformed(java.awt.event.ActionEvent e) {
			    TreePath path = extension.getScriptsPanel().getTree().getSelectionPath();
			    if (path != null) {
			    	ScriptNode node = (ScriptNode)path.getLastPathComponent();
                    if (node == null || node.getUserObject() == null || ! (node.getUserObject() instanceof ScriptWrapper)) {
                    	return;
                    }
                	ScriptWrapper script = (ScriptWrapper) node.getUserObject();
                    extension.getExtScript().setEnabled(script, ! script.isEnabled());
			    }
        	}
        });
			
	}
	
    @Override
    public boolean isEnableForComponent(Component invoker) {
        if (invoker.getName() != null && invoker.getName().equals(ScriptsListPanel.TREE)) {
            try {
                JTree tree = (JTree) invoker;
                if (tree.getLastSelectedPathComponent() != null) {
                	if (tree.getSelectionPaths().length != 1) {
                		// Start by just supporting one at a time..
                		return false;
                	}
                    ScriptNode node = (ScriptNode) tree.getLastSelectedPathComponent();
            		this.setEnabled(false);
            		
                    if (node == null || node.getUserObject() == null || ! (node.getUserObject() instanceof ScriptWrapper)) {
                    	return false;
                    	
                    } else {
                    	ScriptWrapper script = (ScriptWrapper) node.getUserObject();
                    	if (script.getType().isEnableable()) {
                        	if (script.isEnabled()) {
                        		this.setText(Constant.messages.getString("scripts.disable.popup"));
                        	} else {
                        		this.setText(Constant.messages.getString("scripts.enable.popup"));
                        	}
                   			this.setEnabled(true);
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
