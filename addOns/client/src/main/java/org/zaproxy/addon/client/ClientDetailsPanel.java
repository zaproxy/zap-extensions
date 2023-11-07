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

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.util.List;
import javax.swing.ImageIcon;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.AbstractPanel;
import org.zaproxy.zap.view.LayoutHelper;

public class ClientDetailsPanel extends AbstractPanel {

    private static final long serialVersionUID = 1L;

    private JScrollPane scrollPane;
    private JPanel introPanel;
    private ClientNodeDetailsPanel nodeDetailsPanel;

    public ClientDetailsPanel() {
        super();

        this.setLayout(new GridBagLayout());
        setName(Constant.messages.getString(ExtensionClientIntegration.PREFIX + ".details.title"));
        setIcon(
                new ImageIcon(
                        ExtensionClientIntegration.class.getResource(
                                ExtensionClientIntegration.RESOURCES
                                        + "/application-browser.png")));

        introPanel = new JPanel();
        introPanel.setLayout(new GridBagLayout());
        introPanel.add(
                new JLabel(),
                LayoutHelper.getGBC(
                        0, 1, 1, 1.0, 0.0, GridBagConstraints.BOTH, new Insets(2, 2, 2, 2)));

        nodeDetailsPanel = new ClientNodeDetailsPanel();

        scrollPane = new JScrollPane(introPanel);
        add(
                scrollPane,
                LayoutHelper.getGBC(
                        0, 1, 1, 1.0, 1.0, GridBagConstraints.BOTH, new Insets(2, 2, 2, 2)));
    }

    public void setClientNode(ClientNode node) {
        this.nodeDetailsPanel.setClientNode(node);
        scrollPane.setViewportView(nodeDetailsPanel);
        this.setTabFocus();
    }

    public String getCurrentUrl() {
        return this.nodeDetailsPanel.getCurrentUrl();
    }

    public void clear() {
        this.nodeDetailsPanel.clear();
    }

    public List<ClientSideComponent> getSelectedRows() {
        return nodeDetailsPanel.getSelectedRows();
    }
}
