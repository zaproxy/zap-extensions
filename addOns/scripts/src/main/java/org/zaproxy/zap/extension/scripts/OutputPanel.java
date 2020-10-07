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
import java.awt.EventQueue;
import javax.script.ScriptException;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JToolBar;
import javax.swing.text.DefaultCaret;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.AbstractPanel;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.utils.FontUtils;
import org.zaproxy.zap.utils.ZapTextArea;
import org.zaproxy.zap.view.ZapToggleButton;

public class OutputPanel extends AbstractPanel {

    private static final long serialVersionUID = -947074835463140074L;
    private static final Logger logger = Logger.getLogger(OutputPanel.class);

    private static final ImageIcon CLEAR_ICON =
            new ImageIcon(
                    OutputPanel.class.getResource(
                            "/org/zaproxy/zap/extension/scripts/resources/icons/broom.png"));
    private static final ImageIcon CLEAR_ON_RUN_DISABLED_ICON =
            new ImageIcon(
                    OutputPanel.class.getResource(
                            "/org/zaproxy/zap/extension/scripts/resources/icons/broom-play-disabled.png"));
    private static final ImageIcon CLEAR_ON_RUN_ENABLED_ICON =
            new ImageIcon(
                    OutputPanel.class.getResource(
                            "/org/zaproxy/zap/extension/scripts/resources/icons/broom-play-enabled.png"));
    private static final ImageIcon SCROLL_LOCK_DISABLED_ICON =
            new ImageIcon(
                    OutputPanel.class.getResource(
                            "/org/zaproxy/zap/extension/scripts/resources/icons/ui-scroll-pane.png"));
    private static final ImageIcon SCROLL_LOCK_ENABLED_ICON =
            new ImageIcon(
                    OutputPanel.class.getResource(
                            "/org/zaproxy/zap/extension/scripts/resources/icons/ui-scroll-lock-pane.png"));

    private ExtensionScriptsUI extension;
    private JPanel mainPanel;
    private JToolBar mainToolBar;
    private JScrollPane jScrollPane = null;
    private ZapTextArea txtOutput = null;
    private boolean clearOnRun = false;

    /** @param extension */
    public OutputPanel(ExtensionScriptsUI extension) {
        super();
        this.extension = extension;
        initialize();
    }

    /** This method initializes this */
    private void initialize() {
        this.setLayout(new BorderLayout());
        this.setName("ConsoleOutputPanel");
        this.add(getMainPanel(), BorderLayout.CENTER);
    }

    private JPanel getMainPanel() {
        if (mainPanel == null) {
            mainPanel = new JPanel(new BorderLayout());
            mainPanel.add(getToolBar(), BorderLayout.PAGE_START);
            mainPanel.add(getJScrollPane(), BorderLayout.CENTER);
        }
        return mainPanel;
    }

    private JToolBar getToolBar() {
        if (mainToolBar == null) {
            mainToolBar = new JToolBar();
            mainToolBar.setEnabled(true);
            mainToolBar.setFloatable(false);
            mainToolBar.setRollover(true);

            final JButton clearButton = new JButton();
            clearButton.setToolTipText(
                    Constant.messages.getString("scripts.output.clear.button.toolTip"));
            clearButton.setIcon(DisplayUtils.getScaledIcon(CLEAR_ICON));
            clearButton.addActionListener(
                    new java.awt.event.ActionListener() {
                        @Override
                        public void actionPerformed(java.awt.event.ActionEvent e) {
                            getTxtOutput().setText("");
                        }
                    });

            final ZapToggleButton clearOnRunButton = new ZapToggleButton();
            clearOnRunButton.setToolTipText(
                    Constant.messages.getString(
                            "scripts.output.clearOnRun.button.disabled.toolTip"));
            clearOnRunButton.setSelectedToolTipText(
                    Constant.messages.getString(
                            "scripts.output.clearOnRun.button.enabled.toolTip"));
            clearOnRunButton.setIcon(DisplayUtils.getScaledIcon(CLEAR_ON_RUN_DISABLED_ICON));
            clearOnRunButton.setSelectedIcon(DisplayUtils.getScaledIcon(CLEAR_ON_RUN_ENABLED_ICON));
            clearOnRunButton.addActionListener(
                    new java.awt.event.ActionListener() {
                        @Override
                        public void actionPerformed(java.awt.event.ActionEvent e) {
                            clearOnRun = clearOnRunButton.isSelected();
                        }
                    });

            final ZapToggleButton scrollLockButton = new ZapToggleButton();
            scrollLockButton.setToolTipText(
                    Constant.messages.getString(
                            "scripts.output.scrolllock.button.disabled.toolTip"));
            scrollLockButton.setSelectedToolTipText(
                    Constant.messages.getString(
                            "scripts.output.scrolllock.button.enabled.toolTip"));
            scrollLockButton.setIcon(DisplayUtils.getScaledIcon(SCROLL_LOCK_DISABLED_ICON));
            scrollLockButton.setSelectedIcon(DisplayUtils.getScaledIcon(SCROLL_LOCK_ENABLED_ICON));
            scrollLockButton.addActionListener(
                    new java.awt.event.ActionListener() {
                        @Override
                        public void actionPerformed(java.awt.event.ActionEvent e) {
                            if (scrollLockButton.isSelected()) {
                                DefaultCaret caret = (DefaultCaret) getTxtOutput().getCaret();
                                caret.setUpdatePolicy(DefaultCaret.NEVER_UPDATE);
                            } else {
                                DefaultCaret caret = (DefaultCaret) getTxtOutput().getCaret();
                                caret.setUpdatePolicy(DefaultCaret.ALWAYS_UPDATE);
                                getTxtOutput()
                                        .setCaretPosition(getTxtOutput().getDocument().getLength());
                            }
                        }
                    });

            final ZapToggleButton scriptLockButton = new ZapToggleButton();
            scriptLockButton.setToolTipText(
                    Constant.messages.getString(
                            "scripts.output.scriptLock.button.disabled.toolTip"));
            scriptLockButton.setSelectedToolTipText(
                    Constant.messages.getString(
                            "scripts.output.scriptLock.button.enabled.toolTip"));
            scriptLockButton.setIcon(DisplayUtils.getScaledIcon(ExtensionScriptsUI.ICON));
            scriptLockButton.addActionListener(
                    new java.awt.event.ActionListener() {
                        @Override
                        public void actionPerformed(java.awt.event.ActionEvent e) {
                            extension.setLockOutputToDisplayedScript(scriptLockButton.isSelected());
                        }
                    });

            mainToolBar.add(clearButton);
            mainToolBar.add(clearOnRunButton);
            mainToolBar.add(scrollLockButton);
            mainToolBar.add(scriptLockButton);
        }
        return mainToolBar;
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
            jScrollPane.setName("ConsoleScrollPane");
            jScrollPane.setHorizontalScrollBarPolicy(
                    javax.swing.JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
            jScrollPane.setFont(FontUtils.getFont("Dialog"));
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
            txtOutput.setFont(FontUtils.getFont("Dialog"));
            txtOutput.setName("");
            txtOutput.setComponentPopupMenu(ZapPopupMenu.INSTANCE);
        }
        return txtOutput;
    }

    public void append(final String msg) {
        if (EventQueue.isDispatchThread()) {
            getTxtOutput().append(msg);
            return;
        }
        try {
            EventQueue.invokeAndWait(
                    new Runnable() {
                        @Override
                        public void run() {
                            getTxtOutput().append(msg);
                        }
                    });
        } catch (Exception e) {
            if (e instanceof InterruptedException) {
                // Ignore - stop button likely to have been used
            } else {
                logger.error(e.getMessage(), e);
            }
        }
    }

    public void appendError(String str) {
        this.append(str);
        this.append("\n");
    }

    public void append(final ScriptException e) {
        if (Constant.isDevBuild()) {
            logger.error(e.getMessage(), e);
        }
        this.appendError(e.getMessage());
    }

    public void append(final Exception e) {
        if (Constant.isDevBuild()) {
            logger.error(e.getMessage(), e);
        }
        Throwable cause = e.getCause();
        while (cause != null) {
            if (cause instanceof ScriptException) {
                // This is the most useful message
                this.appendError(cause.getMessage());
                return;
            }
            cause = cause.getCause();
        }
        // This will have to do
        this.appendError(e.toString());
    }

    public void preScriptInvoke() {
        if (this.clearOnRun) {
            clear();
        }
    }

    protected boolean isClearOnRun() {
        return this.clearOnRun;
    }

    public void clear() {
        getTxtOutput().setText("");
    }

    public boolean isEmpty() {
        return getTxtOutput().getText().length() == 0;
    }
}
