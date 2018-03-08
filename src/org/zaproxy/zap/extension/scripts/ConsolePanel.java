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
import java.awt.Toolkit;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.io.IOException;
import java.lang.ref.WeakReference;
import java.lang.reflect.Method;
import java.util.Collections;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JSplitPane;
import javax.swing.JToolBar;
import javax.swing.KeyStroke;
import javax.swing.SwingUtilities;

import org.apache.log4j.Logger;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.AbstractPanel;
import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.tab.Tab;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.utils.FontUtils;
import org.zaproxy.zap.view.LayoutHelper;
import org.zaproxy.zap.view.ZapToggleButton;

public class ConsolePanel extends AbstractPanel implements Tab {

	private static final long serialVersionUID = 1L;

	private static final String BASE_NAME_SCRIPT_EXECUTOR_THREAD = "ZAP-ScriptExecutor-";
	private static final ImageIcon AUTO_COMPLETE_ICON = new ImageIcon(OutputPanel.class.getResource(
			"/org/zaproxy/zap/extension/scripts/resources/icons/ui-text-field-suggestion.png"));
	private static final String THREAD_NAME = "ZAP-ScriptChangeOnDiskThread";
	
	private ExtensionScriptsUI extension;
	private JPanel panelContent = null;
	private JToolBar panelToolbar = null;
	private JButton runButton = null;
	private JButton stopButton = null;
	private ZapToggleButton autoCompleteButton = null;
	private JLabel scriptTitle = null;
	private CommandPanel commandPanel = null;
	private OutputPanel outputPanel = null;
	private KeyListener listener = null;
	
	private ScriptWrapper script = null;
	private ScriptWrapper template = null;

	private Map<ScriptWrapper, WeakReference<ScriptExecutorThread>> runnableScriptsToThreadMap;

	// TODO remove once a later version of ZAP has been published
	private Boolean after2_7_0 = null;
	private Method scriptHasChangedOnDiskMethod = null;
	private Method scriptReloadMethod = null;
	private Runnable dialogRunnable = null;
	private Thread changesPollingThread = null;
	private boolean pollForChanges;
	private static final Object [] SCRIPT_CHANGED_BUTTONS = new Object[] {
			Constant.messages.getString("scripts.changed.keep"),
			Constant.messages.getString("scripts.changed.replace")};

	private static final Logger LOG = Logger.getLogger(ConsolePanel.class);

	public ConsolePanel(ExtensionScriptsUI extension) {
		super();
		this.extension = extension;
		initialize();
	}

	private void initialize() {
		this.setIcon(new ImageIcon(ZAP.class.getResource("/resource/icon/16/059.png")));	// 'script' icon
		this.setDefaultAccelerator(KeyStroke.getKeyStroke(
				KeyEvent.VK_C, Toolkit.getDefaultToolkit().getMenuShortcutKeyMask() | KeyEvent.ALT_DOWN_MASK | KeyEvent.SHIFT_DOWN_MASK, false));
		this.setMnemonic(Constant.messages.getChar("scripts.panel.mnemonic"));
		this.setLayout(new BorderLayout());
		if (isAfter2_7_0()) {
			// Scripts changed on disk will now be detected by the core
			startPollingForChanges();
		}

		runnableScriptsToThreadMap = Collections.synchronizedMap(new HashMap<ScriptWrapper, WeakReference<ScriptExecutorThread>>());

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
	
	
	private Method getScriptHasChangedOnDiskMethod() {
		if (after2_7_0 == null) {
			// not tried yet
			try {
				scriptHasChangedOnDiskMethod = ScriptWrapper.class.getMethod("hasChangedOnDisk");
				after2_7_0 = Boolean.TRUE;
			} catch (Exception e) {
				after2_7_0 = Boolean.FALSE;
			}
		}
		return scriptHasChangedOnDiskMethod;
	}
	
	
	private boolean isAfter2_7_0 () {
		if (after2_7_0 == null) {
			// Sets after2_7_0 as a side effect
			getScriptHasChangedOnDiskMethod();
		}
		return after2_7_0;
	}
	
	private boolean isScriptUpdatedOnDisk() {
		if (script != null) {
			// Check to see if its also changed on disk
			try {
				Object result = getScriptHasChangedOnDiskMethod().invoke(script);
				if (result instanceof Boolean) {
					return (Boolean)result;
				} else {
					LOG.error("ScriptWrapper.isChanged() unexpected return " + result + " " + result.getClass().getCanonicalName());
				}
			} catch (Exception e) {
				LOG.error(e.getMessage(), e);
			}
		}
	return false;
	}

	private void startPollingForChanges() {
		changesPollingThread = new Thread() {
			@Override
			public void run() {
				this.setName(THREAD_NAME);
				pollForChanges = true;
				while (pollForChanges) {
					if (dialogRunnable == null && isScriptUpdatedOnDisk() ) {

						dialogRunnable = new Runnable() {
							@Override
							public void run() {
								String message;
								if (script.isChanged()) {
									message = Constant.messages.getString("scripts.console.changedOnDiskAndConsole");
								} else {
									message = Constant.messages.getString("scripts.console.changedOnDisk");
								}
								
								if (JOptionPane.showOptionDialog(
										ConsolePanel.this,
										message,
										Constant.PROGRAM_NAME,
										JOptionPane.YES_NO_OPTION, 
										JOptionPane.WARNING_MESSAGE, 
										null, 
										SCRIPT_CHANGED_BUTTONS,
										null) == JOptionPane.YES_OPTION) {
									try {
										extension.getExtScript().saveScript(script);
									} catch (IOException e) {
										LOG.error(e.getMessage(), e);
									}
								} else {
									reloadScript();
								}
								dialogRunnable = null;
							}
						};
						try {
							SwingUtilities.invokeAndWait(dialogRunnable);
						} catch (Exception e) {
							LOG.error(e.getMessage(), e);
						}
					}
					try {
						sleep(5000);
					} catch (InterruptedException e) {
						// Ignore
					}
				}
				changesPollingThread = null;
			}
		};
		changesPollingThread.setDaemon(true);
		changesPollingThread.start();
		
		if (dialogRunnable != null) {
			return;
		}
	}
	
	private void reloadScript() {
		if (this.scriptReloadMethod == null) {
			try {
				scriptReloadMethod = ScriptWrapper.class.getMethod("reloadScript");
			} catch (Exception e) {
				LOG.error(e.getMessage(), e);
			}
		}
		try {
			this.scriptReloadMethod.invoke(this.script);
			this.updateCommandPanelState(this.script);
		} catch (Exception e) {
			LOG.error(e.getMessage(), e);
		}
	}
	
	private javax.swing.JToolBar getPanelToolbar() {
		if (panelToolbar == null) {
			
			panelToolbar = new javax.swing.JToolBar();
			panelToolbar.setLayout(new java.awt.GridBagLayout());
			panelToolbar.setEnabled(true);
			panelToolbar.setFloatable(false);
			panelToolbar.setRollover(true);
			panelToolbar.setPreferredSize(new java.awt.Dimension(800,30));
			panelToolbar.setFont(FontUtils.getFont("Dialog"));
			panelToolbar.setName("ParamsToolbar");
			
			panelToolbar.add(this.getRunButton(), LayoutHelper.getGBC(0, 0, 1, 0.0D));
			panelToolbar.add(this.getStopButton(), LayoutHelper.getGBC(1, 0, 1, 0.0D));
			panelToolbar.add(this.getAutoCompleteButton(), LayoutHelper.getGBC(2, 0, 1, 0.0D));
			panelToolbar.add(this.getScriptTitle(), LayoutHelper.getGBC(3, 0, 1, 0.0D));
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

	private static String getSyntaxForScript (String engine) {
		String engineLc = engine.toLowerCase(Locale.ROOT);
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

	private static String getSyntaxForExtension (String name) {
		String nameLc = name.toLowerCase(Locale.ROOT);
		if (nameLc.endsWith(".js")) {
			return SyntaxConstants.SYNTAX_STYLE_JAVASCRIPT;
		} else if (nameLc.endsWith(".html")) {
			return SyntaxConstants.SYNTAX_STYLE_HTML;
		} else if (nameLc.endsWith(".css")) {
			return SyntaxConstants.SYNTAX_STYLE_CSS;
		} else {
			return SyntaxConstants.SYNTAX_STYLE_NONE;
		}
	}

	private JButton getRunButton() {
		if (runButton == null) {
			runButton = new JButton();
			runButton.setText(Constant.messages.getString("scripts.toolbar.label.run"));
			runButton.setIcon(DisplayUtils.getScaledIcon(
					new ImageIcon(ZAP.class.getResource("/resource/icon/16/131.png"))));	// 'play' icon
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
			stopButton.setIcon(DisplayUtils.getScaledIcon(
					new ImageIcon(ZAP.class.getResource("/resource/icon/16/142.png"))));	// 'stop' icon
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

	private ZapToggleButton getAutoCompleteButton() {
		if (autoCompleteButton == null) {
			autoCompleteButton = new ZapToggleButton();
			autoCompleteButton.setIcon(DisplayUtils.getScaledIcon(AUTO_COMPLETE_ICON));
			autoCompleteButton.setSelectedIcon(DisplayUtils.getScaledIcon(AUTO_COMPLETE_ICON));
			autoCompleteButton.setToolTipText(Constant.messages.getString("scripts.toolbar.tooltip.autocomplete.disabled"));
			autoCompleteButton.setSelectedToolTipText(Constant.messages.getString("scripts.toolbar.tooltip.autocomplete.enabled"));
			autoCompleteButton.setSelected(true);

			autoCompleteButton.addActionListener(new java.awt.event.ActionListener() { 
				@Override
				public void actionPerformed(java.awt.event.ActionEvent e) {
					getCommandPanel().setAutoCompleteEnabled(autoCompleteButton.isSelected());
				}
			});
		}
		return autoCompleteButton;
	}

	private void runScript () {
		if (runnableScriptsToThreadMap.containsKey(script)) {
			return;
		}

		getRunButton().setEnabled(false);
		
		getOutputPanel().preScriptInvoke();

		// Update it, in case its been changed
		script.setContents(getCommandScript());

		ScriptExecutorThread scriptExecutorThead = new ScriptExecutorThread(script);
		runnableScriptsToThreadMap.put(script, new WeakReference<>(scriptExecutorThead));
		scriptExecutorThead.start();
		getStopButton().setEnabled(true);
	}
	
	private void stopScript() {
		WeakReference<ScriptExecutorThread> refScriptExecutorThread = runnableScriptsToThreadMap.get(script);
		if (refScriptExecutorThread == null) {
			return;
		}

		ScriptExecutorThread thread = refScriptExecutorThread.get();
		refScriptExecutorThread.clear();
		if (thread != null) {
			thread.terminate();
		}
		runnableScriptsToThreadMap.remove(script);
		updateButtonsState();
	}

	private KeyListener getKeyListener () {
		if (listener == null) {
			listener = new KeyListener() {
				@Override
				public void keyTyped(KeyEvent e) {
					if (script != null && ! script.isChanged()) {
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
			outputPanel = new OutputPanel(extension);
			resetOutputPanel();
		}
		return outputPanel;
	}

	protected void resetOutputPanel() {
		outputPanel.clear();
		outputPanel.append(Constant.messages.getString("scripts.welcome.results"));
	}

	public String getCommandScript() {
		return this.getCommandPanel().getCommandScript();
	}
	
	void unload() {
		getCommandPanel().unload();
		this.pollForChanges = false;
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
        setButtonsAllowRunScript(false);
        getScriptTitle().setText("");
	}

	public void setScript(ScriptWrapper script) {
		this.script = script;
		this.template = null;
		
		getCommandPanel().setEditable(script.getEngine().isTextBased());
		updateButtonsState();
		updateCommandPanelState(script);
		
		if (script.getEngine().isTextBased()) {
			// This causes a lot of pain when recording client side Zest scripts,
			// so only do for text based ones
	        setTabFocus();
		}
		
		if (!isTabVisible()) {
			setTabFocus();
		}
	}
	
	/**
	 * Updates the state of the command panel for the given {@code script}.
	 * <p>
	 * It clears and updates the command panel with the contents of the given {@code script}, sets the syntax style to match the
	 * syntax of the {@code script} and updates the title of the panel with the name of the script engine and name of the
	 * {@code script}. Finally it request focus to this tab.
	 * </p>
	 * 
	 * @param script the script whose state will be used to update the command panel
	 * @see #getCommandPanel()
	 */
	private void updateCommandPanelState(ScriptWrapper script) {
        getCommandPanel().clear();
        getCommandPanel().appendToCommandScript(script.getContents());
        getCommandPanel().setScriptType(script.getTypeName());
        getCommandPanel().setCommandCursorPosition(0);
        if (script.getType().hasCapability(ExtensionScriptsUI.CAPABILITY_EXTERNAL)) {
            getCommandPanel().setSyntax(getSyntaxForExtension(script.getName()));
        } else if (script.getEngine().getSyntaxStyle() != null) {
            getCommandPanel().setSyntax(script.getEngine().getSyntaxStyle());
        } else {
            getCommandPanel().setSyntax(getSyntaxForScript(script.getEngine().getEngineName()));
        }
        this.getScriptTitle().setText(script.getEngine().getLanguageName() + " : " + script.getName());
	}
	
	public void setTemplate(ScriptWrapper template) {
		this.template = template;
		this.script = null;
		
		getCommandPanel().setEditable(false);
		setButtonsAllowRunScript(false);
		updateCommandPanelState(template);
        setTabFocus();
	}

    /**
     * Updates the state of the run and stop buttons for the current script.
     * <p>
     * If the current script is not runnable ({@code ScriptWrapper#isRunableStandalone()} returns {@code false}) the run and
     * stop buttons are disabled. If the current script is runnable the state of the buttons will be updated depending whether
     * the script is already running or not. If the script is already running the run button is disabled and the stop enabled,
     * otherwise the run button will be enabled and the stop button disabled.
     * </p>
     * 
     * @see #script
     * @see #getRunButton()
     * @see #getStopButton()
     * @see #setButtonsAllowRunScript(boolean)
     * @see #updateButtonsStateScriptRunning()
     * @see ScriptWrapper#isRunableStandalone()
     */
    private void updateButtonsState() {
        // The only type that can be run directly from the console
        if (script == null || !script.isRunableStandalone()) {
            setButtonsAllowRunScript(false);
            return;
        }

        WeakReference<ScriptExecutorThread> refScriptExecutorThread = runnableScriptsToThreadMap.get(script);
        if (refScriptExecutorThread == null) {
            setButtonsAllowRunScript(true);
            return;
        }

        ScriptExecutorThread thread = refScriptExecutorThread.get();
        refScriptExecutorThread.clear();
        if (thread != null && thread.isAlive()) {
            updateButtonsStateScriptRunning();
        } else {
            runnableScriptsToThreadMap.remove(script);
            setButtonsAllowRunScript(true);
        }
    }

    /**
     * Sets whether or not the state of the buttons should allow to run a script.
     * <p>
     * It enables the run button if {@code allow} is {@code true}, disables it otherwise. The stop button is set always to be
     * disabled.
     * </p>
     * 
     * @param allow {@code true} to allow to run a script, {@code false} otherwise
     * @see #getRunButton()
     * @see #getStopButton()
     * @see #updateButtonsState()
     * @see #updateButtonsStateScriptRunning()
     */
    private void setButtonsAllowRunScript(boolean allow) {
        getRunButton().setEnabled(allow);
        getStopButton().setEnabled(false);

    }

    /**
     * Updates the run and stop buttons to the state of a running script.
     * <p>
     * It disables the run button and enables the stop button.
     * </p>
     * 
     * @see #getRunButton()
     * @see #getStopButton()
     * @see #setButtonsAllowRunScript(boolean)
     * @see #updateButtonsState()
     */
    private void updateButtonsStateScriptRunning() {
        getRunButton().setEnabled(false);
        getStopButton().setEnabled(true);
    }

    private class ScriptExecutorThread extends Thread {

        private final ScriptWrapper script;

        public ScriptExecutorThread(ScriptWrapper script) {
            super();

            if (script == null) {
                throw new IllegalArgumentException("Parameter script must not be null.");
            }
            this.script = script;

            String name = script.getName();
            if (name.length() > 25) {
                name = name.substring(0, 25);
            }

            setName(BASE_NAME_SCRIPT_EXECUTOR_THREAD + name);
        }

        @Override
        public void run() {
            try {
                extension.getExtScript().invokeScript(script);
            } catch (Exception e) {
                getOutputPanel().append(e);
            } finally {
                WeakReference<ScriptExecutorThread> refScriptExecutorThread = runnableScriptsToThreadMap.remove(script);
                if (refScriptExecutorThread != null) {
                    refScriptExecutorThread.clear();
                }
                updateButtonsState();
            }
        }

        @SuppressWarnings("deprecation")
        public void terminate() {
            if (isAlive()) {
                interrupt();
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    // Ignore
                }
                // Yes, its deprecated, but there are no alternatives, and we have to be able to stop scripts
                stop();
            }
        }
    }
}
