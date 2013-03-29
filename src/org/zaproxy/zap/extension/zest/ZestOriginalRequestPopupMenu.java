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
import java.awt.Container;

import javax.swing.JFrame;

import org.parosproxy.paros.extension.ExtensionPopupMenuItem;
import org.zaproxy.zap.extension.httppanel.Message;
import org.zaproxy.zap.extension.httppanel.view.syntaxhighlight.HttpPanelSyntaxHighlightTextArea;

public class ZestOriginalRequestPopupMenu extends ExtensionPopupMenuItem {

	private static final long serialVersionUID = 1L;
	private Component lastInvoker = null;
    private JFrame parentFrame = null;
    private ExtensionZest extension;
    private String selectedText = null;
    private Message selectedMessage = null;
    
	/**
     * @return Returns the lastInvoker.
     */
    public Component getLastInvoker() {
        return lastInvoker;
    }
    
    /**
	 * This method initializes 
	 * 
	 */
	public ZestOriginalRequestPopupMenu(ExtensionZest extension, String label) {
		super();
		this.setText(label);
		this.extension = extension;
	}
	
	@Override
	public boolean isEnableForComponent(Component invoker) {
		boolean visible = false;

System.out.println("ZestOriginalRequestPopupMenu invoker = " + invoker.getClass().getCanonicalName());
		if (invoker instanceof HttpPanelSyntaxHighlightTextArea) {
			HttpPanelSyntaxHighlightTextArea panel = (HttpPanelSyntaxHighlightTextArea)invoker;

System.out.println("ZestOriginalRequestPopupMenu text = " + panel.getSelectedText());
System.out.println("ZestOriginalRequestPopupMenu isOrig = " + extension.isSelectedZestOriginalRequestMessage(panel.getMessage()));
			
			if ((extension.isSelectedZestOriginalRequestMessage(panel.getMessage()) ||
					extension.isSelectedZestOriginalResponseMessage(panel.getMessage())) &&
					panel.getSelectedText() != null && panel.getSelectedText().length() > 0) {
				this.setEnabled(true);
				visible = true;
				this.selectedText = panel.getSelectedText();
				this.selectedMessage = panel.getMessage();
			}
            setLastInvoker(invoker);
            
            
            Container c = getLastInvoker().getParent();
            while (!(c instanceof JFrame)) {
                c = c.getParent();
            }
            setParentFrame((JFrame) c);
		}
        return visible;
    }
	
    public String getSelectedText() {
		return selectedText;
	}

	public Message getSelectedMessage() {
		return selectedMessage;
	}

	/**
     * @return Returns the parentFrame.
     */
    public JFrame getParentFrame() {
        return parentFrame;
    }

    /**
     * @param parentFrame The parentFrame to set.
     */
    public void setParentFrame(JFrame parentFrame) {
        this.parentFrame = parentFrame;
    }

    /**
     * @param lastInvoker The lastInvoker to set.
     */
    public void setLastInvoker(Component lastInvoker) {
        this.lastInvoker = lastInvoker;
    }
    
}
