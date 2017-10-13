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
import java.awt.Component;
import java.awt.event.KeyListener;

import javax.swing.JScrollPane;

import org.fife.ui.rtextarea.RTextScrollPane;
import org.parosproxy.paros.extension.AbstractPanel;
import org.zaproxy.zap.extension.scripts.autocomplete.ScriptAutoCompleteKeyListener;
import org.zaproxy.zap.utils.FontUtils;

public class CommandPanel extends AbstractPanel {

	private static final long serialVersionUID = -947074835463140074L;

	private JScrollPane jScrollPane = null;
	private SyntaxHighlightTextArea syntaxTxtArea = null;
	private KeyListener listener = null;
	private ScriptAutoCompleteKeyListener autocompleteListener;

	/**
     * 
     */
    public CommandPanel(KeyListener listener) {
        super();
        this.listener = listener;
 		initialize();
    }

	/**
	 * This method initializes this
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
			jScrollPane = new RTextScrollPane((Component) getTxtOutput(), false);
			
			((RTextScrollPane)jScrollPane).setLineNumbersEnabled(true);

			jScrollPane.setName("ConsoleCommandjScrollPane");
			jScrollPane.setFont(FontUtils.getFont("Dialog"));
		}
		return jScrollPane;
	}

	private SyntaxHighlightTextArea getTxtOutput() {
		if (this.syntaxTxtArea == null) {
			this.syntaxTxtArea = new SyntaxHighlightTextArea();
			
			this.syntaxTxtArea.setComponentPopupMenu(ZapPopupMenu.INSTANCE);

			this.autocompleteListener = new ScriptAutoCompleteKeyListener(this.syntaxTxtArea);
			this.syntaxTxtArea.addKeyListener(this.autocompleteListener);
			if (listener != null) {
				this.syntaxTxtArea.addKeyListener(listener);
			}
		}
		return this.syntaxTxtArea;
	}
	
	public void addKeyListener(KeyListener l) {
		
	}
	
	public void setSyntax (String syntax) {
		getTxtOutput().setSyntaxEditingStyle(syntax);
	}


	public void clear() {
	    getTxtOutput().setText("");
	    getTxtOutput().discardAllEdits();
	}

	public String getCommandScript() {
		return getTxtOutput().getText();
	}
	
	protected void appendToCommandScript (String str) {
		getTxtOutput().append(str);
		getTxtOutput().discardAllEdits();
		getTxtOutput().requestFocus();
	}
	
	protected void setCommandCursorPosition (int offset) {
		getTxtOutput().setCaretPosition(offset);
	}
	
	void unload() {
		getTxtOutput().unload();
	}
	
	public void setEditable(boolean editable) {
		getTxtOutput().setEditable(editable);
	}

    public void setScriptType(String typeName) {
        if (this.autocompleteListener != null) {
            this.autocompleteListener.setScriptType(typeName);
        }
    }
    
    public void setAutoCompleteEnabled(boolean enable) {
        if (this.autocompleteListener != null) {
            this.autocompleteListener.setEnabled(enable);
        }
    }
	
}
