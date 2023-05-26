/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.zaproxy.addon.client;

import java.awt.GridBagLayout;
import java.util.Date;
import javax.swing.ImageIcon;
import javax.swing.JScrollPane;
import org.jdesktop.swingx.JXTable;
import org.jdesktop.swingx.renderer.DefaultTableRenderer;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.AbstractPanel;
import org.zaproxy.zap.utils.FontUtils;
import org.zaproxy.zap.view.LayoutHelper;
import org.zaproxy.zap.view.ZapTable;
import org.zaproxy.zap.view.renderer.DateFormatStringValue;

public class ClientHistoryPanel extends AbstractPanel {

    private static final long serialVersionUID = 1L;

    private ClientHistoryTableModel clientHistoryTableModel;
    private ZapTable historyTable;

    public ClientHistoryPanel(ClientHistoryTableModel clientHistoryTableModel) {
        setName(Constant.messages.getString(ExtensionClientIntegration.PREFIX + ".history.title"));
        setIcon(
                new ImageIcon(
                        ExtensionClientIntegration.class.getResource(
                                ExtensionClientIntegration.RESOURCES + "/calendar-browser.png")));
        this.clientHistoryTableModel = clientHistoryTableModel;

        this.setLayout(new GridBagLayout());

        JScrollPane jScrollPane = new JScrollPane();
        jScrollPane.setViewportView(getHistoryTable());
        jScrollPane.setFont(FontUtils.getFont("Dialog"));
        this.add(jScrollPane, LayoutHelper.getGBC(0, 0, 1, 1.0, 1.0));
    }

    private JXTable getHistoryTable() {
        if (historyTable == null) {
            historyTable = new ZapTable(clientHistoryTableModel);

            historyTable.setDefaultRenderer(
                    Date.class, new DefaultTableRenderer(new DateFormatStringValue()));

            // TODO more settings...
            historyTable.setAutoCreateColumnsFromModel(false);
            historyTable.getColumnModel().getColumn(0).setMinWidth(20); // Id
            historyTable.getColumnModel().getColumn(0).setPreferredWidth(25);

            historyTable.getColumnModel().getColumn(1).setMinWidth(100); // Timestamp
            historyTable.getColumnModel().getColumn(1).setPreferredWidth(150);

            historyTable.getColumnModel().getColumn(2).setMinWidth(50); // Type
            historyTable.getColumnModel().getColumn(2).setPreferredWidth(55);

            historyTable.getColumnModel().getColumn(3).setMinWidth(100); // Source
            historyTable.getColumnModel().getColumn(3).setPreferredWidth(300);

            historyTable.getColumnModel().getColumn(4).setMinWidth(5); // #
            historyTable.getColumnModel().getColumn(4).setPreferredWidth(10);

            historyTable.getColumnModel().getColumn(7).setMinWidth(100); // Text
            historyTable.getColumnModel().getColumn(7).setPreferredWidth(300);
        }
        return historyTable;
    }
}
