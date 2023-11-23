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

import java.awt.BorderLayout;
import java.awt.Component;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import javax.swing.ImageIcon;
import javax.swing.JLabel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.SortOrder;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.view.ZapTable;

public class ClientNodeDetailsPanel extends AbstractPanel {

    public static final String CLIENT_DETAILS_NAME = "tableClientDetails";

    private static final long serialVersionUID = 1L;

    private ComponentTableModel componentTableModel;
    private ZapTable table;

    private JLabel urlLabel = new JLabel();

    public ClientNodeDetailsPanel() {
        super();

        this.setLayout(new BorderLayout());
        setName(Constant.messages.getString(ExtensionClientIntegration.PREFIX + ".details.title"));
        setIcon(
                new ImageIcon(
                        ExtensionClientIntegration.class.getResource(
                                ExtensionClientIntegration.RESOURCES
                                        + "/application-browser.png")));

        add(urlLabel, BorderLayout.NORTH);

        table = new ZapTable();
        table.setModel(getComponentTableModel());
        table.setName(CLIENT_DETAILS_NAME);
        table.setSortOrder(0, SortOrder.ASCENDING);
        table.setColumnControlVisible(true);
        table.setComponentPopupMenu(
                new JPopupMenu() {
                    private static final long serialVersionUID = 1L;

                    @Override
                    public void show(Component invoker, int x, int y) {
                        View.getSingleton().getPopupMenu().show(invoker, x, y);
                    }
                });

        add(new JScrollPane(table));
    }

    public void setClientNode(ClientNode node) {
        this.urlLabel.setText(node.getUserObject().getUrl());
        this.getComponentTableModel()
                .setComponents(new ArrayList<>(node.getUserObject().getComponents()));
    }

    public String getCurrentUrl() {
        return this.urlLabel.getText();
    }

    public void clear() {
        this.urlLabel.setText("");
        this.getComponentTableModel().setComponents(new ArrayList<>());
    }

    protected ComponentTableModel getComponentTableModel() {
        if (componentTableModel == null) {
            componentTableModel = new ComponentTableModel();
        }
        return componentTableModel;
    }

    public List<ClientSideComponent> getSelectedRows() {
        return Arrays.stream(table.getSelectedRows())
                .map(table::convertRowIndexToModel)
                .mapToObj(getComponentTableModel()::getComponent)
                .collect(Collectors.toList());
    }
}
