/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2019 The ZAP Development Team
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
package org.zaproxy.zap.extension.websocket.treemap.ui;

import java.awt.Component;
import javax.swing.ImageIcon;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTree;
import javax.swing.tree.DefaultTreeCellRenderer;
import org.zaproxy.zap.extension.websocket.treemap.nodes.structural.WebSocketNodeInterface;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.OverlayIcon;

public class WebSocketTreeCellRenderer extends DefaultTreeCellRenderer {

    private static final long serialVersionUID = 6958752713770131906L;

    public static final ImageIcon INCOMING_MESSAGE_ICON =
            new ImageIcon(
                    WebSocketTreeCellRenderer.class.getResource("/resource/icon/105_gray.png"));
    public static final ImageIcon OUTGOING_MESSAGE_ICON =
            new ImageIcon(
                    WebSocketTreeCellRenderer.class.getResource("/resource/icon/106_gray.png"));

    public static final ImageIcon FOLDER_ROOT_ICON =
            new ImageIcon(WebSocketTreeCellRenderer.class.getResource("/resource/icon/16/094.png"));
    public static final ImageIcon FOLDER_CONNECTED_CHANNEL_ICON =
            new ImageIcon(
                    WebSocketTreeCellRenderer.class.getResource(
                            "/resource/icon/fugue/plug-connect.png"));
    public static final ImageIcon FOLDER_DISCONNECTED_CHANNEL_ICON =
            new ImageIcon(
                    WebSocketTreeCellRenderer.class.getResource(
                            "/resource/icon/fugue/plug-disconnect.png"));

    private WebSocketTreeMapHelperUI helperUI;
    private JPanel panel;

    public WebSocketTreeCellRenderer(WebSocketTreeMapHelperUI helper) {
        this.helperUI = helper;
        panel = helperUI.getTreeMapCellPanel();
        panel.setOpaque(false);
    }

    @Override
    public Component getTreeCellRendererComponent(
            JTree jTree,
            Object value,
            boolean selected,
            boolean expanded,
            boolean leaf,
            int row,
            boolean hasFocus) {

        panel.removeAll();
        WebSocketNodeInterface node = (WebSocketNodeInterface) value;

        if (node != null) {
            super.setPreferredSize(null);
            super.getTreeCellRendererComponent(
                    jTree, value, selected, expanded, leaf, row, hasFocus);

            if (node.isRoot()) {
                panel.add(wrap(FOLDER_ROOT_ICON));
            } else {

                OverlayIcon overlayIcon;

                if (node.getParent().isRoot()) { // Host Folder Node
                    // TODO: Add node.isConnected() in order to add the appropriate icon
                    overlayIcon = new OverlayIcon(FOLDER_CONNECTED_CHANNEL_ICON);
                } else { // Leaf node
                    if (node.getContent() != null && node.getContent().getMessage() != null) {
                        if (node.getContent().getMessage().isOutgoing) {
                            overlayIcon = new OverlayIcon(OUTGOING_MESSAGE_ICON);
                        } else {
                            overlayIcon = new OverlayIcon(INCOMING_MESSAGE_ICON);
                        }
                    } else {
                        overlayIcon = new OverlayIcon(INCOMING_MESSAGE_ICON);
                    }
                }

                panel.add(wrap(DisplayUtils.getScaledIcon(overlayIcon)));
            }
            setText(node.getName());
            setIcon(null);
            panel.add(this);
            return panel;
        }
        return this;
    }

    public JPanel getPanel() {
        return panel;
    }

    private JLabel wrap(ImageIcon icon) {
        JLabel label = new JLabel(icon);
        label.setOpaque(false);
        label.putClientProperty("html.disable", Boolean.TRUE);
        return label;
    }
}
