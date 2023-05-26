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
import javax.swing.ImageIcon;
import javax.swing.JScrollPane;
import javax.swing.JTree;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.AbstractPanel;
import org.zaproxy.zap.view.LayoutHelper;

@SuppressWarnings("serial")
public class ClientMapPanel extends AbstractPanel {

    private static final long serialVersionUID = 1L;
    private ExtensionClientIntegration extension;
    private ClientMap clientMap;
    private JScrollPane scrollPane;

    public ClientMapPanel(ExtensionClientIntegration extension, ClientMap clientMap) {
        super();
        this.extension = extension;
        this.clientMap = clientMap;
        this.scrollPane = new JScrollPane();

        this.setClientMap(clientMap);

        this.setLayout(new GridBagLayout());
        setName(Constant.messages.getString(ExtensionClientIntegration.PREFIX + ".tree.title"));
        setIcon(
                new ImageIcon(
                        ExtensionClientIntegration.class.getResource(
                                ExtensionClientIntegration.RESOURCES
                                        + "/sitemap-application-blue.png")));
        add(
                scrollPane,
                LayoutHelper.getGBC(
                        0, 1, 1, 1.0, 1.0, GridBagConstraints.BOTH, new Insets(2, 2, 2, 2)));
    }

    public void setClientMap(ClientMap clientMap) {
        JTree clientTree = new JTree(clientMap);
        clientTree.setShowsRootHandles(true);
        clientTree.setName("treeClient");
        clientTree.setToggleClickCount(1);
        clientTree.setCellRenderer(new ClientMapTreeCellRenderer());

        clientTree.addTreeSelectionListener(
                e -> {
                    ClientNode node = (ClientNode) clientTree.getLastSelectedPathComponent();
                    if (node == null) {
                        return;
                    }
                    extension.clientNodeSelected(node);
                });
        scrollPane.setViewportView(clientTree);
    }

    public void clear() {
        if (this.clientMap != null) {
            this.clientMap.clear();
        }
    }
}
