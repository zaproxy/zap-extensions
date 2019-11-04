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

import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GridBagLayout;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JToolBar;
import javax.swing.JTree;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.LayoutHelper;

public class WebSocketTreeMapHelperUI {

    private ImageIcon PLUG_PLUS_ICON =
            new ImageIcon(
                    WebSocketMapPanel.class.getResource(
                            "/org/zaproxy/zap/extension/websocket/resources/icons/plug--plus.png"));

    private JPanel treeMapCellPanel = null;
    private JToolBar panelToolbar = null;
    private JButton addNewConnectionButton = null;
    private JPanel webSocketTreePanel = null;

    public WebSocketTreeMapHelperUI() {}

    public JPanel getTreeMapCellPanel() {
        if (treeMapCellPanel == null) {
            treeMapCellPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 4, 2));
        }
        return treeMapCellPanel;
    }

    public javax.swing.JToolBar getPanelToolbar() {
        if (panelToolbar == null) {

            panelToolbar = new javax.swing.JToolBar();
            panelToolbar.setLayout(new GridBagLayout());
            panelToolbar.setEnabled(true);
            panelToolbar.setFloatable(false);
            panelToolbar.setRollover(true);
            panelToolbar.setPreferredSize(new Dimension(800, 30));
            panelToolbar.setName("WebSocket Toolbar");

            panelToolbar.add(getAddNewConnectionButton(), LayoutHelper.getGBC(1, 0, 1, 0.0D));
        }
        return panelToolbar;
    }

    private JButton getAddNewConnectionButton() {
        if (addNewConnectionButton == null) {
            addNewConnectionButton = new JButton();
            // TODO: Check Those References
            addNewConnectionButton.setIcon(DisplayUtils.getScaledIcon(PLUG_PLUS_ICON));
            addNewConnectionButton.setToolTipText(
                    Constant.messages.getString("Add new Connection"));
            // TODO: Add Listener
        }
        return addNewConnectionButton;
    }

    public JPanel getWebSocketTreePanel(JTree webSocketTree) {
        if (webSocketTreePanel == null) {
            webSocketTreePanel = new WebSocketTreePanel(webSocketTree, "sitesPanelScrollPane");
        }
        return webSocketTreePanel;
    }
}
