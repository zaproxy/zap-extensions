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

import java.awt.BorderLayout;
import java.awt.Event;
import java.awt.GridBagLayout;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;

import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JSplitPane;
import javax.swing.JToolBar;
import javax.swing.KeyStroke;

import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.AbstractPanel;
import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.tab.Tab;
import org.zaproxy.zap.view.LayoutHelper;

public class ConsolePanel extends AbstractPanel implements Tab {

	private static final long serialVersionUID = 1L;

	private ExtensionScripts extension;
	private JPanel panelContent = null;
	private JToolBar panelToolbar = null;
	private JButton runButton = null;
	private JButton stopButton = null;
	private JLabel scriptTitle = null;
	private CommandPanel commandPanel = null;
	private OutputPanel outputPanel = null;
	private KeyListener listener = null;
	
	private ScriptWrapper script = null;
	private ScriptWrapper template = null;

	private Thread thread = null;

	//private static final Logger logger = Logger.getLogger(ConsolePanel.class);

	public ConsolePanel(ExtensionScripts extension) {
		super();
		this.extension = extension;
		initialize();
	}

	private void initialize() {
		this.setIcon(new ImageIcon(ZAP.class.getResource("/resource/icon/16/059.png")));	// 'script' icon
		this.setDefaultAccelerator(KeyStroke.getKeyStroke(
				KeyEvent.VK_C, Event.CTRL_MASK | Event.ALT_MASK | Event.SHIFT_MASK, false));
		this.setMnemonic(Constant.messages.getChar("scripts.panel.mnemonic"));
		this.setLayout(new BorderLayout());

		panelContent = new JPanel(new GridBagLayout());
		this.add(panelContent, BorderLayout.CENTER);

		JSplitPane splitPane = new JSplitPane();
		splitPane.setDividerSize(3);
		splitPane.setOrientation(JSplitPane.VERTICAL_SPLIT);
		splitPane.setResizeWeight(0.5D);
		splitPane.setTopComponent(getCommandPanel());
		splitPane.setBottomComponent(getOutputPanel());

		panelContent.add(this.getPanelToolbar(), LayoutHelper.getGBC(0, 0, 1, 1.0D, 0.0D));
		panelContent.add(splitPane, LayoutHelper.getGBC(0, 1, 1, 1.0D, 1.0D));
	}
	
	private javax.swing.JToolBar getPanelToolbar() {
		if (panelToolbar == null) {
			
			panelToolbar = new javax.swing.JToolBar();
			panelToolbar.setLayout(new java.awt.GridBagLayout());
			panelToolbar.setEnabled(true);
			panelToolbar.setFloatable(false);
			panelToolbar.setRollover(true);
			panelToolbar.setPreferredSize(new java.awt.Dimension(800,30));
			panelToolbar.setFont(new java.awt.Font("Dialog", java.awt.Font.PLAIN, 12));
			panelToolbar.setName("ParamsToolbar");
			
			panelToolbar.add(this.getRunButton(), LayoutHelper.getGBC(0, 0, 1, 0.0D));
			panelToolbar.add(this.getStopButton(), LayoutHelper.getGBC(1, 0, 1, 0.0D));
			panelToolbar.add(this.getScriptTitle(), LayoutHelper.getGBC(2, 0, 1, 0.0D));
			panelToolbar.add(new JLabel(), LayoutHelper.getGBC(20, 0, 1, 1.0D));	// Filler
		}
		return panelToolbar;
	}
	
	private JLabel getScriptTitle () {
		if (scriptTitle == null) {
			scriptTitle = new JLabel();
		}
		return scriptTitle;
	}

	private String getSyntaxForScript (String engine) {
		String engineLc = engine.toLowerCase();
		if (engineLc.startsWith("clojure")) {
			return SyntaxConstants.SYNTAX_STYLE_CLOJURE;
		} else if (engineLc.startsWith("groovy")) {
			return SyntaxConstants.SYNTAX_STYLE_GROOVY;
		} else if (engineLc.startsWith("ecmacript")) {
			return SyntaxConstants.SYNTAX_STYLE_JAVASCRIPT;
		} else if (engineLc.startsWith("javascript")) {
			return SyntaxConstants.SYNTAX_STYLE_JAVASCRIPT;
		} else if (engineLc.startsWith("python")) {
			return SyntaxConstants.SYNTAX_STYLE_PYTHON;
		} else if (engineLc.startsWith("ruby")) {
			return SyntaxConstants.SYNTAX_STYLE_RUBY;
		} else if (engineLc.startsWith("scala")) {
			return SyntaxConstants.SYNTAX_STYLE_SCALA;
		} else {
			return SyntaxConstants.SYNTAX_STYLE_NONE;
		}
	}

	private JButton getRunButton() {
		if (runButton == null) {
			runButton = new JButton();
			runButton.setText(Constant.messages.getString("scripts.toolbar.label.run"));
			runButton.setIcon(new ImageIcon(ZAP.class.getResource("/resource/icon/16/131.png")));	// 'play' icon
			runButton.setToolTipText(Constant.messages.getString("scripts.toolbar.tooltip.run"));
			runButton.setEnabled(false);

			runButton.addActionListener(new java.awt.event.ActionListener() { 
				@Override
				public void actionPerformed(java.awt.event.ActionEvent e) {
					runScript();
				}
			});
		}
		return runButton;
	}
	
	private JButton getStopButton() {
		if (stopButton == null) {
			stopButton = new JButton();
			stopButton.setIcon(new ImageIcon(ZAP.class.getResource("/resource/icon/16/142.png")));	// 'stop' icon
			stopButton.setToolTipText(Constant.messages.getString("scripts.toolbar.tooltip.stop"));
			stopButton.setEnabled(false);

			stopButton.addActionListener(new java.awt.event.ActionListener() { 
				@Override
				public void actionPerformed(java.awt.event.ActionEvent e) {
					stopScript();
				}
			});
		}
		return stopButton;
	}

	private void runScript () {
		getRunButton().setEnabled(false);
		getStopButton().setEnabled(true);
		
		getOutputPanel().preScriptInvoke();
		
		thread = new Thread() {
			@Override
			public void run() {
				try {
					// Update it, in case its been changed
					script.setContents(getCommandScript());
					extension.getExtScript().invokeScript(script);
				} catch (Exception e) {
					getOutputPanel().append(e);
				}
				getRunButton().setEnabled(true);
				getStopButton().setEnabled(false);
			}
		};
		thread.start();
	}
	
	@SuppressWarnings("deprecation")
	private void stopScript() {
		if (thread != null && thread.isAlive()) {
			thread.interrupt();
			try {
				Thread.sleep(1000);
			} catch (InterruptedException e) {
				// Ignore
			}
			// Yes, its deprecated, but there are no alternatives, and we have to be able to stop scripts
			thread.stop();
			getRunButton().setEnabled(true);
			getStopButton().setEnabled(false);
		}
	}

	private KeyListener getKeyListener () {
		if (listener == null) {
			listener = new KeyListener() {
				@Override
				public void keyTyped(KeyEvent e) {
					if (! script.isChanged()) {
						extension.getExtScript().setChanged(script, true);
					}
				}
				@Override
				public void keyPressed(KeyEvent e) {
					// Ignore
				}
				@Override
				public void keyReleased(KeyEvent e) {
					// Ignore
				}};
		}
		return listener;
	}

	private CommandPanel getCommandPanel() {
		if (commandPanel == null) {
			commandPanel = new CommandPanel(getKeyListener());
			commandPanel.setEditable(false);
			commandPanel.appendToCommandScript(Constant.messages.getString("scripts.welcome.cmd"));
		}
		return commandPanel;
	}

	protected OutputPanel getOutputPanel() {
		if (outputPanel == null) {
			outputPanel = new OutputPanel();
			outputPanel.append(Constant.messages.getString("scripts.welcome.results"));
		}
		return outputPanel;
	}

	public String getCommandScript() {
		return this.getCommandPanel().getCommandScript();
	}
	
	void unload() {
		getCommandPanel().unload();
	}

	public ScriptWrapper getScript() {
		return script;
	}

	public ScriptWrapper getTemplate() {
		return template;
	}

	public void clearScript() {
		this.script = null;
		getCommandPanel().setEditable(false);
        getCommandPanel().clear();
        getCommandPanel().appendToCommandScript(Constant.messages.getString("scripts.welcome.cmd"));
        getScriptTitle().setText("");
	}

	public void setScript(ScriptWrapper script) {
		this.script = script;
		this.template = null;
		
		getCommandPanel().setEditable(script.getEngine().isTextBased());
        getCommandPanel().clear();
        getCommandPanel().appendToCommandScript(script.getContents());
        getCommandPanel().setCommandCursorPosition(0);
        if (script.getEngine().getSyntaxStyle() != null) {
        	getCommandPanel().setSyntax(script.getEngine().getSyntaxStyle());
        } else {
        	getCommandPanel().setSyntax(getSyntaxForScript(script.getEngine().getEngineName()));
        }
        this.getScriptTitle().setText(script.getEngine().getLanguageName() + " : " + script.getName());
       	// The only type that can be run directly from the console
    	this.getRunButton().setEnabled(ExtensionScript.TYPE_STANDALONE.equals(script.getType().getName()));
        setTabFocus();
	}
	
	public void setTemplate(ScriptWrapper template) {
		this.template = template;
		this.script = null;
		
		getCommandPanel().setEditable(false);
        getCommandPanel().clear();
        getCommandPanel().appendToCommandScript(template.getContents());
        getCommandPanel().setCommandCursorPosition(0);
        if (template.getEngine().getSyntaxStyle() != null) {
        	getCommandPanel().setSyntax(template.getEngine().getSyntaxStyle());
        } else {
        	getCommandPanel().setSyntax(getSyntaxForScript(template.getEngine().getEngineName()));
        }
        this.getScriptTitle().setText(template.getEngine().getLanguageName() + " : " + template.getName());
       	this.getRunButton().setEnabled(false);
        setTabFocus();
	}
	
}
