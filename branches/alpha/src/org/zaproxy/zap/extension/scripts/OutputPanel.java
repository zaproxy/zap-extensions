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
import java.awt.Color;
import java.awt.EventQueue;
import java.awt.event.InputEvent;

import javax.script.ScriptException;
import javax.swing.JScrollPane;

import org.apache.log4j.Logger;
import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.utils.ZapTextArea;

public class OutputPanel extends AbstractPanel {

	private static final long serialVersionUID = -947074835463140074L;
	private static final Logger logger = Logger.getLogger(OutputPanel.class);

	private JScrollPane jScrollPane = null;
	private ZapTextArea txtOutput = null;

	/**
     * 
     */
    public OutputPanel() {
        super();
 		initialize();
    }

	/**
	 * This method initializes this
	 */
	private void initialize() {
        this.setLayout(new CardLayout());
        this.setName("ConsoleOutputPanel");
        this.add(getJScrollPane(), getJScrollPane().getName());
			
	}
	/**
	 * This method initializes jScrollPane	
	 * 	
	 * @return javax.swing.JScrollPane	
	 */    
	private JScrollPane getJScrollPane() {
		if (jScrollPane == null) {
			jScrollPane = new JScrollPane();
			jScrollPane.setViewportView(getTxtOutput());
			jScrollPane.setName("jScrollPane");
			jScrollPane.setHorizontalScrollBarPolicy(javax.swing.JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
			jScrollPane.setFont(new java.awt.Font("Dialog", java.awt.Font.PLAIN, 11));
		}
		return jScrollPane;
	}
	/**
	 * This method initializes txtOutput	
	 * 	
	 * @return org.zaproxy.zap.utils.ZapTextArea	
	 */    
	private ZapTextArea getTxtOutput() {
		if (txtOutput == null) {
			txtOutput = new ZapTextArea();
			txtOutput.setEditable(false);
			txtOutput.setLineWrap(true);
			txtOutput.setFont(new java.awt.Font("Dialog", java.awt.Font.PLAIN, 12));
			txtOutput.setName("");
			txtOutput.addMouseListener(new java.awt.event.MouseAdapter() { 

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
		return txtOutput;
	}

	public void append(final String msg) {
		if (EventQueue.isDispatchThread()) {
			getTxtOutput().append(msg);
			return;
		}
		try {
			EventQueue.invokeAndWait(new Runnable() {
				@Override
				public void run() {
					getTxtOutput().append(msg);
				}
			});
		} catch (Exception e) {
			logger.error(e.getMessage(), e);
		}
	}

	public void append(final ScriptException e) {
		getTxtOutput().setForeground(Color.RED);
		this.append(e.getMessage());
	}

	public void append(final Exception e) {
		getTxtOutput().setForeground(Color.RED);
		this.append(e.getMessage());
	}

	public void clear() {
	    getTxtOutput().setText("");
	    getTxtOutput().setForeground(Color.BLACK);
	}
}
