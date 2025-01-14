/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
package org.zaproxy.addon.commonlib.ui;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.event.KeyEvent;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.swing.AbstractButton;
import javax.swing.Icon;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JToolBar;
import javax.swing.text.DefaultCaret;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.view.OutputPanel;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.help.ExtensionHelp;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.utils.ThreadUtils;
import org.zaproxy.zap.utils.TimeStampUtils;
import org.zaproxy.zap.utils.ZapTextArea;
import org.zaproxy.zap.view.OutputSource;
import org.zaproxy.zap.view.TabbedPanel2;
import org.zaproxy.zap.view.ZapToggleButton;

/**
 * A tabbed version of the output panel that allows multiple sources of output to be displayed in
 * separate tabs.
 *
 * @since 1.31.0
 */
@SuppressWarnings("serial")
public class TabbedOutputPanel extends OutputPanel {

    public static final String ATTRIBUTE_ICON = "commonlib.output.panel.icon";
    public static final String ATTRIBUTE_ADDITIONAL_BUTTONS =
            "commonlib.output.panel.additionalButtons";

    private static final String DEFAULT_OUTPUT_SOURCE_NAME =
            Constant.messages.getString("commonlib.output.panel.default");
    private static final String ERROR_OUTPUT_SOURCE_NAME =
            Constant.messages.getString("commonlib.output.panel.error");

    private static final String CLEAR_BUTTON_TOOL_TIP =
            Constant.messages.getString("commonlib.output.panel.button.clear.toolTip");

    private static final ImageIcon DOC_ICON = getImageIcon("/resource/icon/16/172.png");
    private static final ImageIcon BROOM_ICON = getImageIcon("/resource/icon/fugue/broom.png");
    private static final ImageIcon SCROLL_LOCK_DISABLED_ICON =
            getImageIcon("/org/zaproxy/addon/commonlib/resources/ui-scroll-pane.png");
    private static final ImageIcon SCROLL_LOCK_ENABLED_ICON =
            getImageIcon("/org/zaproxy/addon/commonlib/resources/ui-scroll-lock-pane.png");

    private final TabbedPanel2 tabbedPanel;

    private final Map<String, ZapTextArea> txtOutputs;
    private final Map<String, OutputSource> registeredOutputSources;

    public TabbedOutputPanel() {
        txtOutputs = new HashMap<>();
        registeredOutputSources = new HashMap<>();

        setLayout(new BorderLayout());
        setName(Constant.messages.getString("commonlib.output.panel.title"));
        setIcon(DOC_ICON);
        setDefaultAccelerator(
                View.getSingleton()
                        .getMenuShortcutKeyStroke(KeyEvent.VK_O, KeyEvent.SHIFT_DOWN_MASK, false));
        setMnemonic(Constant.messages.getChar("commonlib.output.panel.mnemonic"));

        tabbedPanel = new TabbedPanel2();
        addNewOutputSource(DEFAULT_OUTPUT_SOURCE_NAME);

        var mainPanel = new JPanel(new BorderLayout());
        mainPanel.add(tabbedPanel, BorderLayout.CENTER);
        add(mainPanel, BorderLayout.CENTER);

        setShowByDefault(true);

        ExtensionHelp.enableHelpKey(this, "commonlib.output.panel");
    }

    @Override
    public void registerOutputSource(OutputSource source) {
        registeredOutputSources.put(source.getName(), source);
    }

    @Override
    public void unregisterOutputSource(OutputSource source) {
        if (txtOutputs.containsKey(source.getName())) {
            for (Component tab : tabbedPanel.getTabList()) {
                if (tab.getName().equals(source.getName())) {
                    tabbedPanel.removeTab((AbstractPanel) tab);
                    break;
                }
            }
            txtOutputs.remove(source.getName());
        }
        registeredOutputSources.remove(source.getName());
    }

    private void addNewOutputSource(String name) {
        if (txtOutputs.containsKey(name)) {
            return;
        }
        Map<String, Object> attributes =
                registeredOutputSources.containsKey(name)
                        ? registeredOutputSources.get(name).getAttributes()
                        : Map.of();

        var outputPanel = new AbstractPanel();
        outputPanel.setName(name);
        outputPanel.setLayout(new BorderLayout());
        if (attributes.containsKey(ATTRIBUTE_ICON)
                && attributes.get(ATTRIBUTE_ICON) instanceof Icon) {
            outputPanel.setIcon((Icon) attributes.get(ATTRIBUTE_ICON));
        }

        ZapTextArea txtOutput = buildOutputTextArea();
        JToolBar toolBar = buildToolbar(txtOutput, attributes);
        outputPanel.add(toolBar, BorderLayout.PAGE_START);
        var jScrollPane = new JScrollPane();
        jScrollPane.setViewportView(txtOutput);
        jScrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        outputPanel.add(jScrollPane, BorderLayout.CENTER);

        boolean hideable = !DEFAULT_OUTPUT_SOURCE_NAME.equals(name);
        boolean visible = tabbedPanel.getTabCount() < 8;
        tabbedPanel.addTab(name, outputPanel.getIcon(), outputPanel, hideable, visible, -1);
        txtOutputs.put(name, txtOutput);
    }

    private static ZapTextArea buildOutputTextArea() {
        var txtOutput = new ZapTextArea();
        txtOutput.setEditable(false);
        txtOutput.setLineWrap(true);
        txtOutput.setName("");
        txtOutput.addMouseListener(
                new java.awt.event.MouseAdapter() {
                    @Override
                    public void mousePressed(java.awt.event.MouseEvent e) {
                        showPopupMenuIfTriggered(e);
                    }

                    @Override
                    public void mouseReleased(java.awt.event.MouseEvent e) {
                        showPopupMenuIfTriggered(e);
                    }

                    private void showPopupMenuIfTriggered(java.awt.event.MouseEvent e) {
                        if (e.isPopupTrigger()) {
                            View.getSingleton()
                                    .getPopupMenu()
                                    .show(e.getComponent(), e.getX(), e.getY());
                        }
                    }
                });
        return txtOutput;
    }

    private static JToolBar buildToolbar(ZapTextArea txtOutput, Map<String, Object> attributes) {
        List<AbstractButton> buttons = new ArrayList<>();

        JButton clearButton = new JButton();
        clearButton.setName("clearButton");
        clearButton.setToolTipText(CLEAR_BUTTON_TOOL_TIP);
        clearButton.setIcon(BROOM_ICON);
        clearButton.addActionListener(e -> txtOutput.setText(""));
        buttons.add(clearButton);

        ZapToggleButton scrollLockButton = new ZapToggleButton();
        scrollLockButton.setName("scrollLockButton");
        scrollLockButton.setToolTipText(
                Constant.messages.getString(
                        "commonlib.output.panel.button.scrolllock.disabled.toolTip"));
        scrollLockButton.setSelectedToolTipText(
                Constant.messages.getString(
                        "commonlib.output.panel.button.scrolllock.enabled.toolTip"));
        scrollLockButton.setIcon(DisplayUtils.getScaledIcon(SCROLL_LOCK_DISABLED_ICON));
        scrollLockButton.setSelectedIcon(DisplayUtils.getScaledIcon(SCROLL_LOCK_ENABLED_ICON));
        scrollLockButton.addActionListener(
                e -> {
                    if (scrollLockButton.isSelected()) {
                        DefaultCaret caret = (DefaultCaret) txtOutput.getCaret();
                        caret.setUpdatePolicy(DefaultCaret.NEVER_UPDATE);
                    } else {
                        DefaultCaret caret = (DefaultCaret) txtOutput.getCaret();
                        caret.setUpdatePolicy(DefaultCaret.ALWAYS_UPDATE);
                        txtOutput.setCaretPosition(txtOutput.getDocument().getLength());
                    }
                });
        buttons.add(scrollLockButton);

        if (attributes.containsKey(ATTRIBUTE_ADDITIONAL_BUTTONS)
                && attributes.get(ATTRIBUTE_ADDITIONAL_BUTTONS) instanceof List) {
            ((List<?>) attributes.get(ATTRIBUTE_ADDITIONAL_BUTTONS))
                    .stream()
                            .filter(button -> button instanceof AbstractButton)
                            .forEach(button -> buttons.add((AbstractButton) button));
        }

        var toolBar = new JToolBar();
        toolBar.setEnabled(true);
        toolBar.setFloatable(false);
        toolBar.setRollover(true);
        buttons.stream()
                .sorted(
                        Comparator.comparing(
                                Component::getName,
                                Comparator.nullsLast(Comparator.naturalOrder())))
                .forEach(toolBar::add);
        return toolBar;
    }

    @Override
    public void append(final String msg) {
        append(msg, DEFAULT_OUTPUT_SOURCE_NAME);
    }

    @Override
    public void append(String msg, String sourceName) {
        if (!txtOutputs.containsKey(sourceName)) {
            addNewOutputSource(sourceName);
        }
        ThreadUtils.invokeAndWaitHandled(() -> doAppend(txtOutputs.get(sourceName), msg));
    }

    @Override
    public void append(final Exception e) {
        append(ExceptionUtils.getStackTrace(e), ERROR_OUTPUT_SOURCE_NAME);
    }

    @Override
    public void appendAsync(final String message) {
        appendAsync(message, DEFAULT_OUTPUT_SOURCE_NAME);
    }

    @Override
    public void appendAsync(String message, String sourceName) {
        ThreadUtils.invokeLater(() -> append(message, sourceName));
    }

    @Override
    public void clear() {
        tabbedPanel.removeAll();
        txtOutputs.clear();
        addNewOutputSource(DEFAULT_OUTPUT_SOURCE_NAME);
    }

    @Override
    public void clear(String sourceName) {
        if (txtOutputs.containsKey(sourceName)) {
            txtOutputs.get(sourceName).setText("");
        }
    }

    private void doAppend(ZapTextArea txtOutput, String message) {
        if (Model.getSingleton()
                .getOptionsParam()
                .getViewParam()
                .isOutputTabTimeStampingEnabled()) {
            txtOutput.append(
                    TimeStampUtils.getTimeStampedMessage(
                            message,
                            Model.getSingleton()
                                    .getOptionsParam()
                                    .getViewParam()
                                    .getOutputTabTimeStampsFormat()));
        } else {
            txtOutput.append(message);
        }
    }

    private static ImageIcon getImageIcon(String resourceName) {
        return DisplayUtils.getScaledIcon(TabbedOutputPanel.class.getResource(resourceName));
    }
}
