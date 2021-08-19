/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.addon.oast.ui;

import java.awt.BorderLayout;
import java.awt.CardLayout;
import javax.swing.Box;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JToolBar;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.AbstractPanel;
import org.zaproxy.addon.oast.ExtensionOast;
import org.zaproxy.addon.oast.OastRequest;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.utils.FontUtils;

public class OastPanel extends AbstractPanel {

    private static final long serialVersionUID = 1L;

    private JToolBar mainToolBar;
    private JPanel mainPanel = null;
    private JScrollPane scrollPane = null;
    private OastTable resultsTable = null;
    private OastTableModel model = null;
    private final ExtensionOast extensionOast;

    public OastPanel(ExtensionOast extensionOast) {
        super();
        this.extensionOast = extensionOast;

        this.setLayout(new CardLayout());
        this.setName(Constant.messages.getString("oast.panel.name"));
        this.setIcon(new ImageIcon(OastPanel.class.getResource("/resource/icon/16/callbacks.png")));
        this.add(getMainPanel(), getMainPanel().getName());
    }

    private javax.swing.JPanel getMainPanel() {
        if (mainPanel == null) {
            mainPanel = new JPanel(new BorderLayout());
            mainPanel.setName("OastPanel");
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
            mainToolBar.setName("Callback Toolbar");

            mainToolBar.add(getClearButton());
            mainToolBar.add(Box.createHorizontalGlue());
            mainToolBar.add(getOptionsButton());
        }
        return mainToolBar;
    }

    private JButton getClearButton() {
        JButton clearButton =
                new JButton(Constant.messages.getString("oast.panel.clear.button.label"));
        clearButton.setToolTipText(Constant.messages.getString("oast.panel.clear.button.toolTip"));
        clearButton.setIcon(
                DisplayUtils.getScaledIcon(
                        new ImageIcon(
                                OastPanel.class.getResource("/resource/icon/fugue/broom.png"))));
        clearButton.addActionListener(e -> extensionOast.deleteAllCallbacks());
        return clearButton;
    }

    private JButton getOptionsButton() {
        JButton optionsButton = new JButton();
        optionsButton.setToolTipText(
                Constant.messages.getString("oast.panel.options.button.label"));
        optionsButton.setIcon(
                DisplayUtils.getScaledIcon(
                        new ImageIcon(OastPanel.class.getResource("/resource/icon/16/041.png"))));
        optionsButton.addActionListener(
                e ->
                        Control.getSingleton()
                                .getMenuToolsControl()
                                .options(Constant.messages.getString("oast.options.title")));
        return optionsButton;
    }

    private JScrollPane getJScrollPane() {
        if (scrollPane == null) {
            scrollPane = new JScrollPane();
            scrollPane.setFont(FontUtils.getFont("Dialog"));
            scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
            scrollPane.setViewportView(getResultsTable());
        }

        return scrollPane;
    }

    private OastTable getResultsTable() {
        if (this.resultsTable == null) {
            this.model = new OastTableModel();
            this.resultsTable = new OastTable(model);
        }
        return this.resultsTable;
    }

    public void addOastRequest(OastRequest oastRequest) {
        model.addEntry(oastRequest);
    }

    public void clearOastRequests() {
        model.clear();
    }
}
