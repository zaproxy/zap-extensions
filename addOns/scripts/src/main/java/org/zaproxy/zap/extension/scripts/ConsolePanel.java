/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2012 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
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
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.io.IOException;
import java.lang.ref.WeakReference;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardWatchEventKinds;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.util.Collections;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import javax.swing.AbstractAction;
import javax.swing.Box;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JSplitPane;
import javax.swing.JToolBar;
import javax.swing.KeyStroke;
import javax.swing.border.EmptyBorder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.AbstractPanel;
import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.utils.FontUtils;
import org.zaproxy.zap.utils.ThreadUtils;
import org.zaproxy.zap.view.LayoutHelper;
import org.zaproxy.zap.view.ZapToggleButton;

@SuppressWarnings("serial")
public class ConsolePanel extends AbstractPanel {

    private static final long serialVersionUID = 1L;

    private static final String BASE_NAME_SCRIPT_EXECUTOR_THREAD = "ZAP-ScriptExecutor-";
    private static final ImageIcon AUTO_COMPLETE_ICON =
            getImageIcon(
                    "/org/zaproxy/zap/extension/scripts/resources/icons/ui-text-field-suggestion.png");
    private static final String THREAD_NAME = "ZAP-ScriptChangeOnDiskThread";

    private ExtensionScriptsUI extension;
    private JPanel panelContent = null;
    private JToolBar panelToolbar = null;
    private JButton saveButton;
    private ZapToggleButton enableButton;
    private JButton runButton = null;
    private JButton stopButton = null;
    private ZapToggleButton autoCompleteButton = null;
    private JButton optionsButton;
    private JLabel scriptTitle = null;
    private CommandPanel commandPanel = null;
    private OutputPanel outputPanel = null;
    private KeyListener listener = null;

    private ScriptWrapper script = null;
    private ScriptWrapper template = null;

    private Map<ScriptWrapper, WeakReference<ScriptExecutorThread>> runnableScriptsToThreadMap;

    private Runnable dialogRunnable = null;
    private Thread changesPollingThread = null;
    private boolean pollForChanges;
    private WatchService watchService;
    private WatchKey scriptWatchKey;
    private static final Object[] SCRIPT_CHANGED_BUTTONS =
            new Object[] {
                Constant.messages.getString("scripts.changed.keep"),
                Constant.messages.getString("scripts.changed.replace")
            };

    private Map<ScriptWrapper, Integer> scriptWrapperToOffset = new HashMap<>();

    private static final Logger LOGGER = LogManager.getLogger(ConsolePanel.class);
    private static final int DEFAULT_MODIFIER =
            Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx();

    public ConsolePanel(ExtensionScriptsUI extension) {
        super();
        this.extension = extension;

        this.setIcon(
                new ImageIcon(ZAP.class.getResource("/resource/icon/16/059.png"))); // 'script' icon
        this.setDefaultAccelerator(
                extension
                        .getView()
                        .getMenuShortcutKeyStroke(
                                KeyEvent.VK_C,
                                KeyEvent.ALT_DOWN_MASK | KeyEvent.SHIFT_DOWN_MASK,
                                false));
        this.setMnemonic(Constant.messages.getChar("scripts.panel.mnemonic"));
        this.setLayout(new BorderLayout());
        startPollingForChanges();

        runnableScriptsToThreadMap =
                Collections.synchronizedMap(
                        new HashMap<ScriptWrapper, WeakReference<ScriptExecutorThread>>());

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

    private boolean isScriptUpdatedOnDisk() {
        if (script == null) {
            return false;
        }
        return script.hasChangedOnDisk();
    }

    private void startPollingForChanges() {
        try {
            watchService = FileSystems.getDefault().newWatchService();
        } catch (IOException e) {
            LOGGER.warn(
                    "Could not create watchService, polling for script changes on disk will be disabled.",
                    e);
            return;
        }

        changesPollingThread =
                new Thread() {
                    @Override
                    public void run() {
                        this.setName(THREAD_NAME);
                        pollForChanges = true;
                        if (watchService == null) {
                            return;
                        }
                        WatchKey watchKey;
                        while (pollForChanges) {
                            try {
                                watchKey = watchService.take();
                            } catch (Exception e) {
                                continue;
                            }
                            for (WatchEvent<?> event : watchKey.pollEvents()) {
                                try {
                                    Path changedPath =
                                            ((Path) scriptWatchKey.watchable())
                                                    .resolve((Path) event.context());
                                    if (!Files.isSameFile(changedPath, script.getFile().toPath())) {
                                        continue;
                                    }
                                } catch (Exception e) {
                                    continue;
                                }
                                if (isScriptUpdatedOnDisk()) {
                                    promptUserToKeepOrReplaceScript();
                                }
                            }
                            watchKey.reset();
                        }
                        changesPollingThread = null;
                    }
                };
        changesPollingThread.setDaemon(true);
        changesPollingThread.start();
    }

    private void promptUserToKeepOrReplaceScript() {
        if (dialogRunnable == null) {
            dialogRunnable =
                    () -> {
                        if (getSaveOrReplaceScriptChoice() == JOptionPane.YES_OPTION) {
                            try {
                                extension.getExtScript().saveScript(script);
                            } catch (IOException e) {
                                LOGGER.error(e.getMessage(), e);
                            }
                        } else {
                            reloadScript();
                        }
                        dialogRunnable = null;
                    };
            ThreadUtils.invokeAndWaitHandled(dialogRunnable);
        }
    }

    private int getSaveOrReplaceScriptChoice() {
        ScriptConsoleOptions options = extension.getScriptConsoleOptions();
        if (script.isChanged()) {
            return JOptionPane.showOptionDialog(
                    ConsolePanel.this,
                    Constant.messages.getString("scripts.console.changedOnDiskAndConsole"),
                    Constant.PROGRAM_NAME,
                    JOptionPane.YES_NO_OPTION,
                    JOptionPane.WARNING_MESSAGE,
                    null,
                    SCRIPT_CHANGED_BUTTONS,
                    null);
        }

        if (options.getDefaultScriptChangedBehaviour()
                == ScriptConsoleOptions.DefaultScriptChangedBehaviour.ASK_EACH_TIME) {
            var checkBox =
                    new JCheckBox(Constant.messages.getString("scripts.console.rememberChoice"));
            int choice =
                    JOptionPane.showOptionDialog(
                            ConsolePanel.this,
                            new Object[] {
                                Constant.messages.getString("scripts.console.changedOnDisk"),
                                checkBox
                            },
                            Constant.PROGRAM_NAME,
                            JOptionPane.YES_NO_OPTION,
                            JOptionPane.WARNING_MESSAGE,
                            null,
                            SCRIPT_CHANGED_BUTTONS,
                            null);
            if (checkBox.isSelected()) {
                options.setDefaultScriptChangedBehaviour(
                        choice == JOptionPane.YES_OPTION
                                ? ScriptConsoleOptions.DefaultScriptChangedBehaviour.KEEP
                                : ScriptConsoleOptions.DefaultScriptChangedBehaviour.REPLACE);
            }
            return choice;
        }

        return options.getDefaultScriptChangedBehaviour()
                        == ScriptConsoleOptions.DefaultScriptChangedBehaviour.KEEP
                ? JOptionPane.YES_OPTION
                : JOptionPane.NO_OPTION;
    }

    private void reloadScript() {
        try {
            this.script.reloadScript();
            this.updateCommandPanelState(this.script);
        } catch (Exception e) {
            LOGGER.error(e.getMessage(), e);
        }
    }

    private JToolBar getPanelToolbar() {
        if (panelToolbar == null) {
            panelToolbar = new JToolBar();
            panelToolbar.setEnabled(true);
            panelToolbar.setFloatable(false);
            panelToolbar.setRollover(true);
            panelToolbar.setFont(FontUtils.getFont("Dialog"));
            panelToolbar.setName("Script Console Toolbar");

            panelToolbar.add(getSaveButton());
            panelToolbar.add(getEnableButton());
            panelToolbar.addSeparator();
            panelToolbar.add(getRunButton());
            panelToolbar.add(getStopButton());
            panelToolbar.addSeparator();
            panelToolbar.add(getAutoCompleteButton());
            panelToolbar.addSeparator();
            panelToolbar.add(getScriptTitle());
            panelToolbar.add(Box.createHorizontalGlue());
            panelToolbar.add(getOptionsButton());
        }
        return panelToolbar;
    }

    private JLabel getScriptTitle() {
        if (scriptTitle == null) {
            scriptTitle = new JLabel();
            scriptTitle.setBorder(new EmptyBorder(0, 5, 0, 5));
        }
        return scriptTitle;
    }

    private static String getSyntaxForScript(String engine) {
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

    private static String getSyntaxForExtension(String name) {
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

    private JButton getSaveButton() {
        if (saveButton == null) {
            saveButton = new JButton();
            saveButton.setIcon(getImageIcon("/resource/icon/16/096.png")); // diskette icon
            saveButton.setToolTipText(Constant.messages.getString("scripts.toolbar.tooltip.save"));
            saveButton.setEnabled(false);

            saveButton.addActionListener(
                    e -> {
                        if (script == null) {
                            return;
                        }
                        extension.getScriptsPanel().saveScript(script);
                    });
        }
        return saveButton;
    }

    private ZapToggleButton getEnableButton() {
        if (enableButton == null) {
            enableButton = new ZapToggleButton();
            enableButton.setEnabled(false);

            enableButton.setIcon(
                    getImageIcon(
                            "/org/zaproxy/zap/extension/scripts/resources/icons/cross-white.png"));
            enableButton.setToolTipText(
                    Constant.messages.getString("scripts.toolbar.tooltip.enable"));

            enableButton.setSelectedIcon(
                    getImageIcon(
                            "/org/zaproxy/zap/extension/scripts/resources/icons/tick-circle.png"));
            enableButton.setSelectedToolTipText(
                    Constant.messages.getString("scripts.toolbar.tooltip.disable"));

            enableButton.addActionListener(
                    e -> {
                        if (script == null || !script.getType().isEnableable()) {
                            return;
                        }
                        extension.getExtScript().setEnabled(script, enableButton.isSelected());
                    });
        }
        return enableButton;
    }

    private JButton getRunButton() {
        if (runButton == null) {
            runButton = new JButton();
            runButton.setText(Constant.messages.getString("scripts.toolbar.label.run"));
            runButton.setIcon(getImageIcon("/resource/icon/16/131.png")); // 'play' icon
            runButton.setToolTipText(Constant.messages.getString("scripts.toolbar.tooltip.run"));
            runButton.setEnabled(false);

            runButton.addActionListener(e -> runScript());
        }
        return runButton;
    }

    private JButton getStopButton() {
        if (stopButton == null) {
            stopButton = new JButton();
            stopButton.setIcon(getImageIcon("/resource/icon/16/142.png")); // 'stop' icon
            stopButton.setToolTipText(Constant.messages.getString("scripts.toolbar.tooltip.stop"));
            stopButton.setEnabled(false);

            stopButton.addActionListener(e -> stopScript());
        }
        return stopButton;
    }

    private ZapToggleButton getAutoCompleteButton() {
        if (autoCompleteButton == null) {
            autoCompleteButton = new ZapToggleButton();
            autoCompleteButton.setIcon(AUTO_COMPLETE_ICON);
            autoCompleteButton.setSelectedIcon(AUTO_COMPLETE_ICON);
            autoCompleteButton.setToolTipText(
                    Constant.messages.getString("scripts.toolbar.tooltip.autocomplete.disabled"));
            autoCompleteButton.setSelectedToolTipText(
                    Constant.messages.getString("scripts.toolbar.tooltip.autocomplete.enabled"));
            autoCompleteButton.setSelected(true);

            autoCompleteButton.addActionListener(
                    e -> getCommandPanel().setAutoCompleteEnabled(autoCompleteButton.isSelected()));
        }
        return autoCompleteButton;
    }

    private JButton getOptionsButton() {
        if (optionsButton == null) {
            optionsButton = new JButton();
            optionsButton.setToolTipText(
                    Constant.messages.getString("scripts.toolbar.tooltip.consoleOptions"));
            optionsButton.setIcon(getImageIcon("/resource/icon/16/041.png"));

            optionsButton.addActionListener(
                    e ->
                            Control.getSingleton()
                                    .getMenuToolsControl()
                                    .options(
                                            Constant.messages.getString(
                                                    "scripts.options.console.title")));
        }
        return optionsButton;
    }

    private void runScript() {
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
        WeakReference<ScriptExecutorThread> refScriptExecutorThread =
                runnableScriptsToThreadMap.get(script);
        if (refScriptExecutorThread == null) {
            return;
        }

        ScriptExecutorThread thread = refScriptExecutorThread.get();
        refScriptExecutorThread.clear();
        if (thread != null) {
            thread.terminate();
        }
        runnableScriptsToThreadMap.remove(script);
        updateRunButtonStates();
    }

    private KeyListener getKeyListener() {
        if (listener == null) {
            listener =
                    new KeyListener() {

                        @Override
                        public void keyTyped(KeyEvent e) {
                            // Ignore ctrl+S character code
                            if (e.getKeyChar() == KeyEvent.VK_PAUSE) {
                                return;
                            }
                            if (script != null && !script.isChanged()) {
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
                        }
                    };
        }
        return listener;
    }

    private static ImageIcon getImageIcon(String resourceName) {
        return DisplayUtils.getScaledIcon(
                new ImageIcon(ConsolePanel.class.getResource(resourceName)));
    }

    CommandPanel getCommandPanel() {
        if (commandPanel == null) {
            commandPanel = new CommandPanel(getKeyListener());
            commandPanel.setEditable(false);
            commandPanel.setCommandScript(Constant.messages.getString("scripts.welcome.cmd"));
            String saveScriptActionKey = "scripts.action.saveScript";
            commandPanel
                    .getInputMap(WHEN_IN_FOCUSED_WINDOW)
                    .put(
                            KeyStroke.getKeyStroke(KeyEvent.VK_S, DEFAULT_MODIFIER),
                            saveScriptActionKey);
            commandPanel
                    .getActionMap()
                    .put(
                            saveScriptActionKey,
                            new AbstractAction() {
                                @Override
                                public void actionPerformed(ActionEvent e) {
                                    if (script == null) {
                                        return;
                                    }
                                    extension.getScriptsPanel().saveScript(script);
                                }
                            });
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
        if (watchService != null) {
            try {
                watchService.close();
            } catch (Exception ignored) {
            }
        }
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
        getCommandPanel().setCommandScript(Constant.messages.getString("scripts.welcome.cmd"));
        getSaveButton().setEnabled(false);
        getEnableButton().setEnabled(false);
        setButtonsAllowRunScript(false);
        getScriptTitle().setText("");
    }

    public void removeScript(ScriptWrapper script) {
        scriptWrapperToOffset.remove(script);
    }

    public void setScript(ScriptWrapper script) {
        setScript(script, true);
    }

    public void setScript(ScriptWrapper script, boolean allowFocus) {
        if (this.script != null) {
            // Save the offset
            scriptWrapperToOffset.put(this.script, getCommandPanel().getCommandCursorPosition());
        }
        if (scriptWatchKey != null) {
            scriptWatchKey.cancel();
        }
        this.script = script;
        this.template = null;

        if (script.getFile() != null && watchService != null) {
            try {
                scriptWatchKey =
                        script.getFile()
                                .toPath()
                                .getParent()
                                .register(watchService, StandardWatchEventKinds.ENTRY_MODIFY);
            } catch (IOException e) {
                LOGGER.warn(
                        "Failed to register watchService for script file: {}", script.getFile(), e);
            }
        }

        getCommandPanel().setEditable(script.getEngine().isTextBased());
        updateButtonStates();
        updateCommandPanelState(script);
        if (isScriptUpdatedOnDisk()) {
            promptUserToKeepOrReplaceScript();
        }
        if (!allowFocus) {
            return;
        }
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
     *
     * <p>It clears and updates the command panel with the contents of the given {@code script},
     * sets the syntax style to match the syntax of the {@code script} and updates the title of the
     * panel with the name of the script engine and name of the {@code script}. Finally it request
     * focus to this tab.
     *
     * @param script the script whose state will be used to update the command panel
     * @see #getCommandPanel()
     */
    private void updateCommandPanelState(ScriptWrapper script) {
        getCommandPanel().setCommandScript(script.getContents());
        getCommandPanel().setScriptType(script.getTypeName());
        if (this.scriptWrapperToOffset.containsKey(script)) {
            getCommandPanel().setCommandCursorPosition(this.scriptWrapperToOffset.get(script));
        } else {
            getCommandPanel().setCommandCursorPosition(0);
        }
        if (script.getType().hasCapability(ExtensionScriptsUI.CAPABILITY_EXTERNAL)) {
            getCommandPanel().setSyntax(getSyntaxForExtension(script.getName()));
        } else if (script.getEngine().getSyntaxStyle() != null) {
            getCommandPanel().setSyntax(script.getEngine().getSyntaxStyle());
        } else {
            getCommandPanel().setSyntax(getSyntaxForScript(script.getEngine().getEngineName()));
        }
        this.getScriptTitle()
                .setText(script.getEngine().getLanguageName() + " : " + script.getName());
    }

    public void setTemplate(ScriptWrapper template) {
        this.template = template;
        this.script = null;

        getCommandPanel().setEditable(false);
        getSaveButton().setEnabled(false);
        getEnableButton().setEnabled(false);
        setButtonsAllowRunScript(false);
        updateCommandPanelState(template);
        setTabFocus();
    }

    void updateButtonStates() {
        updateRunButtonStates();
        if (script != null) {
            getSaveButton().setEnabled(script.isChanged() && script.getEngine() != null);
            getEnableButton().setEnabled(script.getType().isEnableable());
            getEnableButton().setSelected(script.isEnabled());
        } else {
            getSaveButton().setEnabled(false);
            getEnableButton().setEnabled(false);
        }
    }

    /**
     * Updates the state of the run and stop buttons for the current script.
     *
     * <p>If the current script is not runnable ({@code ScriptWrapper#isRunableStandalone()} returns
     * {@code false}) the run and stop buttons are disabled. If the current script is runnable the
     * state of the buttons will be updated depending whether the script is already running or not.
     * If the script is already running the run button is disabled and the stop enabled, otherwise
     * the run button will be enabled and the stop button disabled.
     *
     * @see #script
     * @see #getRunButton()
     * @see #getStopButton()
     * @see #setButtonsAllowRunScript(boolean)
     * @see #updateButtonsStateScriptRunning()
     * @see ScriptWrapper#isRunnableStandalone()
     */
    private void updateRunButtonStates() {
        // The only type that can be run directly from the console
        if (script == null || !script.isRunnableStandalone()) {
            setButtonsAllowRunScript(false);
            return;
        }

        WeakReference<ScriptExecutorThread> refScriptExecutorThread =
                runnableScriptsToThreadMap.get(script);
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
     *
     * <p>It enables the run button if {@code allow} is {@code true}, disables it otherwise. The
     * stop button is set always to be disabled.
     *
     * @param allow {@code true} to allow to run a script, {@code false} otherwise
     * @see #getRunButton()
     * @see #getStopButton()
     * @see #updateRunButtonStates()
     * @see #updateButtonsStateScriptRunning()
     */
    private void setButtonsAllowRunScript(boolean allow) {
        getRunButton().setEnabled(allow);
        getStopButton().setEnabled(false);
    }

    /**
     * Updates the run and stop buttons to the state of a running script.
     *
     * <p>It disables the run button and enables the stop button.
     *
     * @see #getRunButton()
     * @see #getStopButton()
     * @see #setButtonsAllowRunScript(boolean)
     * @see #updateRunButtonStates()
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
                WeakReference<ScriptExecutorThread> refScriptExecutorThread =
                        runnableScriptsToThreadMap.remove(script);
                if (refScriptExecutorThread != null) {
                    refScriptExecutorThread.clear();
                }
                updateRunButtonStates();
            }
        }

        @SuppressWarnings({"deprecation", "removal"})
        public void terminate() {
            if (isAlive()) {
                interrupt();
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    // Ignore
                }
                // Yes, its deprecated, but there are no alternatives, and we have to be able to
                // stop scripts
                stop();
            }
        }
    }
}
