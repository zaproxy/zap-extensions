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

import javax.swing.text.JTextComponent;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionPopupMenuItem;
import org.zaproxy.zap.extension.zest.ExtensionZest;
import org.zaproxy.zap.extension.zest.ZestScriptWrapper;

public class ZestPasteVariableMenu extends ExtensionPopupMenuItem {

	private static final long serialVersionUID = 2282358266003940700L;

	private ExtensionZest extension;
	private String variable;
	private JTextComponent lastInvoker = null;
    private ZestScriptWrapper script = null;

	/**
	 * This method initializes 
	 * 
	 */
	public ZestPasteVariableMenu(ExtensionZest extension, JTextComponent lastInvoker, String variable) {
		super(variable);
System.out.println("PVM lastInvoker=" + lastInvoker);
		this.variable = variable;
		this.extension = extension;
		this.lastInvoker = lastInvoker;
		this.initialize();
	}
	
	protected void initialize() {
        this.addActionListener(new java.awt.event.ActionListener() { 

        	@Override
        	public void actionPerformed(java.awt.event.ActionEvent e) {
        		// TODO get correct delimiters
        		lastInvoker.replaceSelection("{{" + variable + "}}");
        		/*
        		if (lastInvoker instanceof JTextArea) {
        			JTextArea jta = (JTextArea) lastInvoker;
        			//jta.insert("{{" + variable + "}}", jta.getCaretPosition());
        			jta.replaceSelection("{{" + variable + "}}");
        		} else if (lastInvoker instanceof JTextField) {
        			JTextField jtf = (JTextField) lastInvoker;
        			jtf.getCaretPosition();
        			jtf.rep
        			
        		}
        		*/
        	}
        });

	}

	/**/
    @Override
    public String getParentMenuName() {
    	return Constant.messages.getString("zest.pastevar.popup", true);
    }
    
    @Override
    public boolean isSubMenu() {
    	return true;
    }

    @Override
    public boolean isEnableForComponent(Component invoker) {
    	return true;
    }
	@Override
    public boolean isSafe() {
    	return true;
    }
}
