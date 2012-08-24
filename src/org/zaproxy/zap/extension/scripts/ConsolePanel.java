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
import java.awt.GridBagLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.util.List;

import javax.script.ScriptException;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JSplitPane;
import javax.swing.JToolBar;
import javax.swing.SwingWorker;

import org.apache.commons.configuration.ConfigurationException;
import org.apache.log4j.Logger;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.model.Model;
import org.zaproxy.zap.extension.brk.BreakPanel;
import org.zaproxy.zap.extension.search.SearchPanel;
import org.zaproxy.zap.extension.tab.Tab;
import org.zaproxy.zap.view.LayoutHelper;

public class ConsolePanel extends AbstractPanel implements Tab {

	private static final long serialVersionUID = 1L;

	private ExtensionScripts extension;
	private JPanel panelContent = null;
	private JToolBar panelToolbar = null;
	private JComboBox engineOptions = null;
	private JButton runButton = null;
	private JButton stopButton = null;
	private JButton loadButton = null;
	private JButton saveButton = null;
	private CommandPanel commandPanel = null;
	private OutputPanel outputPanel = null;

	private SwingWorker worker = null;
	private Thread thread = null;

	private final Logger logger = Logger.getLogger(ConsolePanel.class);

	public ConsolePanel(ExtensionScripts extension) {
		super();
		this.extension = extension;
		initialize();
	}

	private void initialize() {
		this.setIcon(new ImageIcon(BreakPanel.class.getResource("/resource/icon/16/059.png")));	// 'script' icon
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
			
			panelToolbar.add(this.getEngineOptions(), LayoutHelper.getGBC(0, 0, 1, 0.0D));
			panelToolbar.add(this.getRunButton(), LayoutHelper.getGBC(1, 0, 1, 0.0D));
			panelToolbar.add(this.getStopButton(), LayoutHelper.getGBC(2, 0, 1, 0.0D));
			panelToolbar.add(this.getLoadButton(), LayoutHelper.getGBC(3, 0, 1, 0.0D));
			panelToolbar.add(this.getSaveButton(), LayoutHelper.getGBC(4, 0, 1, 0.0D));
			panelToolbar.add(new JLabel(), LayoutHelper.getGBC(20, 0, 1, 1.0D));	// Filler
		}
		return panelToolbar;
	}
	
	private JComboBox getEngineOptions() {
		if (this.engineOptions == null) {
			this.engineOptions = new JComboBox();
			List<String> engineNames = extension.getScriptingEngines();
			for (String name : engineNames) {
				this.engineOptions.addItem(name);
			}
			String defaultScript = extension.getScriptParam().getDefaultScript();
			if (defaultScript != null) {
				this.engineOptions.setSelectedItem(defaultScript);
				setSyntaxForScript (defaultScript);
			}
			
			this.engineOptions.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent e) {
					setSyntaxForScript (engineOptions.getSelectedItem().toString());
					
					extension.getScriptParam().setDefaultScript(engineOptions.getSelectedItem().toString());
					try {
						extension.getScriptParam().getConfig().save();
					} catch (ConfigurationException e1) {
						logger.error("Failed to save config file " + e1.getMessage(), e1);
					}
				}});
			

		}
		return this.engineOptions;
	}
	
	private void setSyntaxForScript (String engine) {
		String engineLc = engine.toLowerCase();
		if (engineLc.startsWith("clojure")) {
			getCommandPanel().setSyntax(SyntaxConstants.SYNTAX_STYLE_CLOJURE);
		} else if (engineLc.startsWith("groovy")) {
			getCommandPanel().setSyntax(SyntaxConstants.SYNTAX_STYLE_GROOVY);
		} else if (engineLc.startsWith("ecmacript")) {
			getCommandPanel().setSyntax(SyntaxConstants.SYNTAX_STYLE_JAVASCRIPT);
		} else if (engineLc.startsWith("javascript")) {
			getCommandPanel().setSyntax(SyntaxConstants.SYNTAX_STYLE_JAVASCRIPT);
		} else if (engineLc.startsWith("python")) {
			getCommandPanel().setSyntax(SyntaxConstants.SYNTAX_STYLE_PYTHON);
		} else if (engineLc.startsWith("ruby")) {
			getCommandPanel().setSyntax(SyntaxConstants.SYNTAX_STYLE_RUBY);
		} else if (engineLc.startsWith("scala")) {
			getCommandPanel().setSyntax(SyntaxConstants.SYNTAX_STYLE_SCALA);
		} else {
			getCommandPanel().setSyntax(SyntaxConstants.SYNTAX_STYLE_NONE);
		}
		
	}

	private JButton getRunButton() {
		if (runButton == null) {
			runButton = new JButton();
			runButton.setText(ExtensionScripts.getMessageString("scripts.toolbar.label.run"));
			runButton.setIcon(new ImageIcon(SearchPanel.class.getResource("/resource/icon/16/131.png")));	// 'play' icon
			runButton.setToolTipText(ExtensionScripts.getMessageString("scripts.toolbar.tooltip.run"));

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
			stopButton.setIcon(new ImageIcon(SearchPanel.class.getResource("/resource/icon/16/142.png")));	// 'stop' icon
			stopButton.setToolTipText(ExtensionScripts.getMessageString("scripts.toolbar.tooltip.stop"));
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

	private JButton getLoadButton() {
		if (loadButton == null) {
			loadButton = new JButton();
			loadButton.setIcon(new ImageIcon(SearchPanel.class.getResource("/resource/icon/16/047.png")));	// 'open folder' icon
			loadButton.setToolTipText(ExtensionScripts.getMessageString("scripts.toolbar.tooltip.load"));

			loadButton.addActionListener(new java.awt.event.ActionListener() { 
				@Override
				public void actionPerformed(java.awt.event.ActionEvent e) {
					loadScript();
				}
			});
		}
		return loadButton;
	}
	
	private JButton getSaveButton() {
		if (saveButton == null) {
			saveButton = new JButton();
			saveButton.setIcon(new ImageIcon(SearchPanel.class.getResource("/resource/icon/16/096.png")));	// 'diskette' icon
			saveButton.setToolTipText(ExtensionScripts.getMessageString("scripts.toolbar.tooltip.save"));

			saveButton.addActionListener(new java.awt.event.ActionListener() { 
				@Override
				public void actionPerformed(java.awt.event.ActionEvent e) {
					saveScript();
				}
			});
		}
		return saveButton;
	}
	

	private void runScript () {
		getRunButton().setEnabled(false);
		getLoadButton().setEnabled(false);
		getSaveButton().setEnabled(false);
		getStopButton().setEnabled(true);
		
		getOutputPanel().clear();
		
		thread = new Thread() {
			@Override
			public void run() {
				try {
					extension.runScript(getEngineOptions().getSelectedItem().toString(), getCommandScript(), 
							new OutputPanelWriter(getOutputPanel()));
				} catch (ScriptException se) {
					getOutputPanel().append(se);
				} catch (Exception ie) {
					getOutputPanel().append(ie);
				}
				getRunButton().setEnabled(true);
				getLoadButton().setEnabled(true);
				getSaveButton().setEnabled(true);
				getStopButton().setEnabled(false);
			}
		};
		thread.start();
	}
	
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
			getLoadButton().setEnabled(true);
			getSaveButton().setEnabled(true);
			getStopButton().setEnabled(false);
		}
	}

	private void loadScript() {
		String dir = extension.getScriptParam().getDefaultDir();
		if (dir == null || dir.length() == 0) {
			dir = Model.getSingleton().getOptionsParam().getUserDirectory().getAbsolutePath();
		}
		
	    JFileChooser chooser = new JFileChooser(dir);
		File file = null;
	    int rc = chooser.showOpenDialog(this);
	    if(rc == JFileChooser.APPROVE_OPTION) {
    		file = chooser.getSelectedFile();
    		if (file == null) {
    			return;
    		}
    		extension.getScriptParam().setDefaultDir(chooser.getCurrentDirectory().getAbsolutePath());
    	    BufferedReader fr = null;
            try {
                fr = new BufferedReader(new FileReader(file));
                getCommandPanel().clear();
                String line;
                while ((line = fr.readLine()) != null) {
                    getCommandPanel().appendToCommandScript(line + "\n");
                }

            } catch (Exception e1) {
            	logger.error(e1.getMessage(), e1);
                extension.getView().showWarningDialog(Constant.messages.getString("file.load.error") + " " + file.getAbsolutePath() + ".");
            } finally {
        	    try {
        	        fr.close();
        	    } catch (Exception e2) {
                	logger.error(e2.getMessage(), e2);
        	    }
            }
	    }
	}

	private void saveScript() {
		String dir = extension.getScriptParam().getDefaultDir();
		if (dir == null || dir.length() == 0) {
			dir = Model.getSingleton().getOptionsParam().getUserDirectory().getAbsolutePath();
		}
		
	    JFileChooser chooser = new JFileChooser(dir);
		File file = null;
	    int rc = chooser.showSaveDialog(this);
	    if(rc == JFileChooser.APPROVE_OPTION) {
    		file = chooser.getSelectedFile();
    		if (file == null) {
    			return;
    		}
    		extension.getScriptParam().setDefaultDir(chooser.getCurrentDirectory().getAbsolutePath());
    	    BufferedWriter fw = null;
            try {
                fw = new BufferedWriter(new FileWriter(file, false));
                fw.append(getCommandScript());

            } catch (Exception e1) {
            	logger.error(e1.getMessage(), e1);
                extension.getView().showWarningDialog(Constant.messages.getString("file.save.error") + " " + file.getAbsolutePath() + ".");
            } finally {
        	    try {
        	        fw.close();
        	    } catch (Exception e2) {
                	logger.error(e2.getMessage(), e2);
        	    }
            }
	    }
	}

	private CommandPanel getCommandPanel() {
		if (commandPanel == null) {
			commandPanel = new CommandPanel();
		}
		return commandPanel;
	}

	private OutputPanel getOutputPanel() {
		if (outputPanel == null) {
			outputPanel = new OutputPanel();
			outputPanel.append(ExtensionScripts.getMessageString("scripts.welcome"));
		}
		return outputPanel;
	}

	public String getCommandScript() {
		return this.getCommandPanel().getCommandScript();
	}
}
