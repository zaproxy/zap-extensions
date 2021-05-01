/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2013 The ZAP Development Team
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
package org.zaproxy.zap.extension.zest;

import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.event.KeyEvent;
import java.util.List;
import javax.swing.Box;
import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JToolBar;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.model.HistoryReference;
import org.zaproxy.zap.extension.httppanel.Message;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.utils.FontUtils;
import org.zaproxy.zap.view.table.HistoryReferencesTable;

public class ZestResultsPanel extends AbstractPanel {

    private static final long serialVersionUID = 1L;

    public static final String TABLE_NAME = "ZestResultsTable";

    @SuppressWarnings("unused")
    private ExtensionZest extension = null;

    private JToolBar toolBar;
    private javax.swing.JPanel zestPanel = null;
    private JScrollPane jScrollPane = null;
    private HistoryReferencesTable resultsTable = null;
    private ZestResultsTableModel model = null;

    public ZestResultsPanel(ExtensionZest extension) {
        super();
        this.extension = extension;
        this.setLayout(new CardLayout());
        this.setName(Constant.messages.getString("zest.results.panel.title"));
        this.setIcon(ExtensionZest.ZEST_ICON);
        this.setDefaultAccelerator(
                this.extension
                        .getView()
                        .getMenuShortcutKeyStroke(KeyEvent.VK_Z, KeyEvent.SHIFT_DOWN_MASK, false));
        this.setMnemonic(Constant.messages.getChar("zest.results.panel.mnemonic"));

        this.add(getZestPanel(), getZestPanel().getName());
    }

    private JToolBar getToolBar() {
        if (toolBar == null) {
            toolBar = new JToolBar();
            toolBar.setFloatable(false);
            toolBar.setRollover(true);

            JButton clearButton =
                    new JButton(
                            Constant.messages.getString("zest.results.panel.button.clear"),
                            DisplayUtils.getScaledIcon(
                                    ZestResultsPanel.class.getResource(
                                            "/resource/icon/fugue/broom.png")));
            clearButton.addActionListener(e -> model.clear());

            JButton optionsButton =
                    new JButton(
                            DisplayUtils.getScaledIcon(
                                    ZestResultsPanel.class.getResource(
                                            "/resource/icon/16/041.png")));
            optionsButton.setToolTipText(
                    Constant.messages.getString("zest.results.panel.button.options"));
            optionsButton.addActionListener(
                    e ->
                            Control.getSingleton()
                                    .getMenuToolsControl()
                                    .options(Constant.messages.getString("zest.options.title")));

            toolBar.add(clearButton);
            toolBar.add(Box.createHorizontalGlue());
            toolBar.add(optionsButton);
        }
        return toolBar;
    }

    private javax.swing.JPanel getZestPanel() {
        if (zestPanel == null) {
            zestPanel = new JPanel(new BorderLayout());
            zestPanel.setName("ZestResultsPanel");
            zestPanel.add(getToolBar(), BorderLayout.PAGE_START);
            zestPanel.add(getJScrollPane(), BorderLayout.CENTER);
        }
        return zestPanel;
    }

    private JScrollPane getJScrollPane() {
        if (jScrollPane == null) {
            jScrollPane = new JScrollPane();
            jScrollPane.setFont(FontUtils.getFont("Dialog"));
            jScrollPane.setHorizontalScrollBarPolicy(
                    javax.swing.JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
            jScrollPane.setViewportView(getResultsTable());
        }
        return jScrollPane;
    }

    private HistoryReferencesTable getResultsTable() {
        if (this.resultsTable == null) {
            this.model = new ZestResultsTableModel();
            this.resultsTable = new HistoryReferencesTable(model);
            this.resultsTable.setName(TABLE_NAME);
        }
        return this.resultsTable;
    }

    protected ZestResultsTableModel getModel() {
        return model;
    }

    public boolean isSelectedMessage(Message message) {
        List<HistoryReference> hrefs = this.getResultsTable().getSelectedHistoryReferences();

        if (hrefs.size() == 1) {
            try {
                return hrefs.get(0).getHttpMessage().hashCode() == message.hashCode();
            } catch (Exception e) {
                // Ignore
            }
        }
        return false;
    }
}
