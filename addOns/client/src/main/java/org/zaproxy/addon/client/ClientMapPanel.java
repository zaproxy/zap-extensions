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

import java.awt.Component;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.swing.ImageIcon;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JTree;
import javax.swing.LookAndFeel;
import javax.swing.UIManager;
import javax.swing.tree.TreePath;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.view.LayoutHelper;

@SuppressWarnings("serial")
public class ClientMapPanel extends AbstractPanel {

    public static final String CLIENT_TREE_NAME = "treeClient";

    private static final long serialVersionUID = 1L;
    private ExtensionClientIntegration extension;
    private JTree clientTree;
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
        clientTree = new JTree(clientMap);
        clientTree.setShowsRootHandles(true);
        clientTree.setName(CLIENT_TREE_NAME);
        clientTree.setToggleClickCount(1);
        clientTree.setCellRenderer(new ClientMapTreeCellRenderer());
        clientTree.setComponentPopupMenu(new ClientCustomPopupMenu());

        // Let the cell renderer define the height to properly show the icons.
        LookAndFeel laf = UIManager.getLookAndFeel();
        if (laf != null
                && Constant.isMacOsX()
                && UIManager.getSystemLookAndFeelClassName().equals(laf.getClass().getName())) {
            clientTree.setRowHeight(0);
        }

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

    public List<ClientNode> getSelectedNodes() {
        return Stream.ofNullable(clientTree.getSelectionPaths())
                .flatMap(Stream::of)
                .map(TreePath::getLastPathComponent)
                .map(ClientNode.class::cast)
                .collect(Collectors.toList());
    }

    public void deleteNodes(List<ClientNode> nodes) {
        for (ClientNode node : nodes) {
            if (!node.isRoot()) {
                clientMap.removeNodeFromParent(node);
            }
        }
    }

    public ClientNode getSelectedNode() {
        return (ClientNode) clientTree.getSelectionPath().getLastPathComponent();
    }

    public ExtensionClientIntegration getExtension() {
        return extension;
    }

    protected class ClientCustomPopupMenu extends JPopupMenu {
        private static final long serialVersionUID = 1L;

        @Override
        public void show(Component invoker, int x, int y) {
            TreePath tp = clientTree.getPathForLocation(x, y);
            if (tp != null) {
                boolean select = true;
                // Only select a new item if the current item is not
                // already selected - this is to allow multiple items
                // to be selected
                if (clientTree.getSelectionPaths() != null) {
                    for (TreePath t : clientTree.getSelectionPaths()) {
                        if (t.equals(tp)) {
                            select = false;
                            break;
                        }
                    }
                }
                if (select) {
                    clientTree.getSelectionModel().setSelectionPath(tp);
                }
            }
            View.getSingleton().getPopupMenu().show(invoker, x, y);
        }
    }
}
