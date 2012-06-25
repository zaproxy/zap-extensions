/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2012 The ZAP development team
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

import java.awt.CardLayout;
import java.awt.event.InputEvent;

import javax.swing.JScrollPane;

import org.fife.ui.rtextarea.RTextScrollPane;
import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.view.View;

public class CommandPanel extends AbstractPanel {

	private static final long serialVersionUID = -947074835463140074L;

	private JScrollPane jScrollPane = null;
	private SyntaxHighlightTextArea syntaxTxtArea = null;

	/**
     * 
     */
    public CommandPanel() {
        super();
 		initialize();
    }

	/**
	 * This method initializes this
	 * 
	 * @return void
	 */
	private void initialize() {
        this.setLayout(new CardLayout());
        this.setName("ConsoleCommandPanel");

        this.add(getJScrollPane(), getJScrollPane().getName());
			
	}
	/**
	 * This method initializes jScrollPane	
	 * 	
	 * @return javax.swing.JScrollPane	
	 */    
	private JScrollPane getJScrollPane() {
		if (jScrollPane == null) {
			jScrollPane = new RTextScrollPane(getTxtOutput(), false);
			
			((RTextScrollPane)jScrollPane).setLineNumbersEnabled(true);

			jScrollPane.setName("ConsoleCommandjScrollPane");
			jScrollPane.setHorizontalScrollBarPolicy(javax.swing.JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
			jScrollPane.setFont(new java.awt.Font("Dialog", java.awt.Font.PLAIN, 11));
		}
		return jScrollPane;
	}

	private SyntaxHighlightTextArea getTxtOutput() {
		if (this.syntaxTxtArea == null) {
			this.syntaxTxtArea = new SyntaxHighlightTextArea();
			
			this.syntaxTxtArea.addMouseListener(new java.awt.event.MouseAdapter() { 

				@Override
				public void mousePressed(java.awt.event.MouseEvent e) {
					mouseAction(e);
				}
					
				@Override
				public void mouseReleased(java.awt.event.MouseEvent e) {
					mouseAction(e);
				}
				
				public void mouseAction(java.awt.event.MouseEvent e) {
					// right mouse button action
					if ((e.getModifiers() & InputEvent.BUTTON3_MASK) != 0 || e.isPopupTrigger()) {
						View.getSingleton().getPopupMenu().show(e.getComponent(), e.getX(), e.getY());
					}
				}
				
			});
		}
		return this.syntaxTxtArea;
	}
	
	public void setSyntax (String syntax) {
		getTxtOutput().setSyntaxEditingStyle(syntax);
	}


	public void clear() {
	    getTxtOutput().setText("");
	}

	public String getCommandScript() {
		return getTxtOutput().getText();
	}
	
	protected void appendToCommandScript (String str) {
		getTxtOutput().append(str);
	}
	
}
