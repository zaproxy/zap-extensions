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
package org.zaproxy.addon.client.ui;

import java.awt.Component;
import java.awt.FlowLayout;
import javax.swing.ImageIcon;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTree;
import javax.swing.tree.DefaultTreeCellRenderer;
import org.zaproxy.addon.client.ExtensionClientIntegration;
import org.zaproxy.addon.client.internal.ClientNode;
import org.zaproxy.addon.client.internal.ClientSideDetails;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.OverlayIcon;

public class ClientMapTreeCellRenderer extends DefaultTreeCellRenderer {

    private static final ImageIcon ROOT_ICON =
            ExtensionClientIntegration.getIcon("sitemap-application-blue.png");
    private static final ImageIcon LEAF_ICON =
            ExtensionClientIntegration.getIcon("blue-document.png");
    private static final ImageIcon FRAGMENT_ICON =
            ExtensionClientIntegration.getIcon("blue-document-number.png");
    private static final ImageIcon FOLDER_OPEN_ICON =
            ExtensionClientIntegration.getIcon("blue-folder-horizontal-open.png");
    private static final ImageIcon FOLDER_CLOSED_ICON =
            ExtensionClientIntegration.getIcon("blue-folder-horizontal.png");
    private static final ImageIcon NOT_VISITED_OVERLAY =
            ExtensionClientIntegration.getIcon("overlay-minus.png");
    private static final ImageIcon REDIRECT_OVERLAY =
            ExtensionClientIntegration.getIcon("overlay-redirect.png");
    private static final ImageIcon CONTENT_LOADED_OVERLAY =
            ExtensionClientIntegration.getIcon("overlay-content-loaded.png");
    private static final ImageIcon DATABASE_ICON =
            ExtensionClientIntegration.getIcon("database.png");

    private static final long serialVersionUID = 1L;

    private JPanel component;

    public ClientMapTreeCellRenderer() {
        this.component = new JPanel(new FlowLayout(FlowLayout.CENTER, 4, 2));
        component.setOpaque(false);
        this.setLabelFor(component);
        this.putClientProperty("html.disable", Boolean.TRUE);
    }

    /** Sets custom tree node logos. */
    @Override
    public Component getTreeCellRendererComponent(
            JTree tree,
            Object value,
            boolean sel,
            boolean expanded,
            boolean leaf,
            int row,
            boolean hasFocus) {

        component.removeAll();
        ClientNode node = null;
        if (value instanceof ClientNode) {
            node = (ClientNode) value;
        }

        if (node != null) {
            setPreferredSize(null); // clears the preferred size, making the node visible
            super.getTreeCellRendererComponent(tree, value, sel, expanded, leaf, row, hasFocus);

            if (node.isRoot()) {
                component.add(wrap(ROOT_ICON));
            } else {
                ClientSideDetails csd = node.getUserObject();
                OverlayIcon icon;
                if (csd.isStorage()) {
                    icon = new OverlayIcon(DATABASE_ICON);
                } else if (leaf) {
                    if (csd.getUrl().contains("#")) {
                        icon = new OverlayIcon(FRAGMENT_ICON);
                    } else {
                        icon = new OverlayIcon(LEAF_ICON);
                    }
                    if (!csd.isVisited()) {
                        icon.add(
                                csd.isContentLoaded()
                                        ? CONTENT_LOADED_OVERLAY
                                        : NOT_VISITED_OVERLAY);
                    } else if (csd.isRedirect()) {
                        icon.add(REDIRECT_OVERLAY);
                    }
                } else {
                    if (expanded) {
                        icon = new OverlayIcon(FOLDER_OPEN_ICON);
                    } else {
                        icon = new OverlayIcon(FOLDER_CLOSED_ICON);
                    }
                }
                component.add(wrap(DisplayUtils.getScaledIcon(icon)));
            }

            setText(node.getUserObject().getName());
            setIcon(null);
            component.add(this);

            return component;
        }

        return this;
    }

    private static JLabel wrap(ImageIcon icon) {
        JLabel label = new JLabel(icon);
        label.setOpaque(false);
        label.putClientProperty("html.disable", Boolean.TRUE);
        return label;
    }
}
