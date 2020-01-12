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

import java.awt.EventQueue;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import javax.swing.ImageIcon;
import javax.swing.JTree;
import javax.swing.LookAndFeel;
import javax.swing.UIManager;
import javax.swing.tree.TreeCellRenderer;
import javax.swing.tree.TreePath;
import javax.swing.tree.TreeSelectionModel;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.model.Model;
import org.zaproxy.zap.extension.httppanel.HttpPanel;
import org.zaproxy.zap.extension.websocket.treemap.nodes.structural.WebSocketNodeInterface;
import org.zaproxy.zap.view.LayoutHelper;

public class WebSocketMapPanel extends AbstractPanel {

    private static final long serialVersionUID = -5534551524380114578L;

    public static final ImageIcon DISCONNECTED_ICON =
            new ImageIcon(
                    WebSocketMapPanel.class.getResource(
                            "/resource/icon/fugue/plug-disconnect.png"));
    public static final ImageIcon CONNECTED_ICON =
            new ImageIcon(
                    WebSocketMapPanel.class.getResource("/resource/icon/fugue/plug-connect.png"));

    //    public static final ImageIcon DISCONNECT_TARGET_ICON =
    //            new ImageIcon(
    //                    WebSocketMapPanel.class.getResource(
    //                            "/resource/icon/fugue/plug-disconnect-target.png"));
    //    public static final ImageIcon CONNECT_TARGET_ICON =
    //            new ImageIcon(
    //                    WebSocketMapPanel.class.getResource(
    //                            "/resource/icon/fugue/plug-connect-target.png"));

    private WebSocketTreeMapModel treeMapModel;

    private WebSocketTreeMapHelperUI helperUI;

    private JTree treeMap = null;

    private WebSocketTreeMapMessagesView messagesView;

    private HttpPanel requestPanel;
    private HttpPanel responsePanel;

    private static final Logger LOGGER = Logger.getLogger(WebSocketMapPanel.class);

    /** Constructor which initialize the Panel */
    public WebSocketMapPanel(
            WebSocketTreeMapModel treeMapModel, WebSocketTreeMapHelperUI helperUI) {
        super();
        this.treeMapModel = treeMapModel;
        this.helperUI = helperUI;

        messagesView = new WebSocketTreeMapMessagesView(treeMapModel);
        initialize();
    }

    private void initialize() {
        super.setHideable(true);
        super.setIcon(DISCONNECTED_ICON);
        super.setName(Constant.messages.getString("websocket.treemap.title"));
        //		this.setDefaultAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_S,
        // Toolkit.getDefaultToolkit().getMenuShortcutKeyMask() | KeyEvent.SHIFT_DOWN_MASK, false));

        if (Model.getSingleton().getOptionsParam().getViewParam().getWmUiHandlingOption() == 0) {
            super.setSize(300, 200);
        }

        super.setLayout(new GridBagLayout());
        //        this.add(
        //                helperUI.getPanelToolbar(),
        //                LayoutHelper.getGBC(0, 0, 1, 0, new Insets(2, 2, 2, 2)));
        super.add(
                helperUI.getWebSocketTreePanel(getTreeSite()),
                LayoutHelper.getGBC(
                        0, 1, 1, 1.0, 1.0, GridBagConstraints.BOTH, new Insets(2, 2, 2, 2)));

        expandRoot();
        //        getTreeSite().addTreeSelectionListener();
    }

    /**
     * This method initializes treeSite
     *
     * @return javax.swing.JTree
     */
    public JTree getTreeSite() {
        if (treeMap == null) {

            treeMap = new JTree(treeMapModel);
            treeMap.setShowsRootHandles(true);
            treeMap.getSelectionModel().setSelectionMode(TreeSelectionModel.SINGLE_TREE_SELECTION);
            treeMap.setName("treeSite");
            treeMap.setToggleClickCount(1);

            // Force macOS L&F to query the row height from SiteMapTreeCellRenderer to hide the
            // filtered nodes.
            // Other L&Fs hide the filtered nodes by default.
            LookAndFeel laf = UIManager.getLookAndFeel();
            if (laf != null
                    && Constant.isMacOsX()
                    && UIManager.getSystemLookAndFeelClassName().equals(laf.getClass().getName())) {
                treeMap.setRowHeight(0);
            }

            // ZAP: Add custom tree cell renderer.
            TreeCellRenderer renderer = new WebSocketTreeCellRenderer(helperUI);
            treeMap.setCellRenderer(renderer);
            treeMap.addTreeSelectionListener(messagesView.getWebSocketTreeMapListener());
        }
        return treeMap;
    }

    public void expandRoot() {
        WebSocketNodeInterface root = (WebSocketNodeInterface) treeMap.getModel().getRoot();
        if (root == null) {
            return;
        }
        final TreePath rootTreePath = new TreePath(root);

        if (EventQueue.isDispatchThread()) {
            getTreeSite().expandPath(rootTreePath);
            return;
        }
        try {
            EventQueue.invokeLater(() -> getTreeSite().expandPath(rootTreePath));
        } catch (Exception e) {
            // ZAP: Log exceptions
            LOGGER.warn(e.getMessage(), e);
        }
    }

    public void setDisplayPanel(HttpPanel requestPanel, HttpPanel responsePanel) {
        this.requestPanel = requestPanel;
        this.responsePanel = responsePanel;

        messagesView.setDisplayPanel(requestPanel, responsePanel);
    }
}
