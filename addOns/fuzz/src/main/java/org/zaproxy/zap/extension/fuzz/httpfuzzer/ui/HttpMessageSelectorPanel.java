/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2015 The ZAP Development Team
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
package org.zaproxy.zap.extension.fuzz.httpfuzzer.ui;

import java.util.Collections;
import javax.swing.GroupLayout;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTree;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreeSelectionModel;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.fuzz.MessageSelectorPanel;
import org.zaproxy.zap.view.SiteMapListener;
import org.zaproxy.zap.view.SiteMapTreeCellRenderer;

public class HttpMessageSelectorPanel implements MessageSelectorPanel<HttpMessage> {

    private static final Logger LOGGER = LogManager.getLogger(HttpMessageSelectorPanel.class);

    private final JPanel panel;
    private final JTree messagesTree;
    private final DefaultTreeModel messagesTreeModel;

    private HttpMessage selectedHttpMessage;

    public HttpMessageSelectorPanel() {
        panel = new JPanel();
        GroupLayout layout = new GroupLayout(panel);
        panel.setLayout(layout);
        layout.setAutoCreateGaps(true);

        SiteNode root =
                new SiteNode(
                        null,
                        -1,
                        Constant.messages.getString(
                                "fuzz.httpfuzzer.select.message.dialogue.rootNode"));
        SiteNode mainTreeRoot = Model.getSingleton().getSession().getSiteTree().getRoot();
        copyTree(mainTreeRoot, root);
        messagesTreeModel = new DefaultTreeModel(root);

        messagesTree = new JTree(messagesTreeModel);
        messagesTree.setVisibleRowCount(10);
        messagesTree.setShowsRootHandles(true);
        messagesTree.setName("HttpMessageSelectorTree");
        messagesTree.getSelectionModel().setSelectionMode(TreeSelectionModel.SINGLE_TREE_SELECTION);
        messagesTree.setCellRenderer(
                new SiteMapTreeCellRenderer(Collections.<SiteMapListener>emptyList()));
        messagesTree.expandRow(0);

        JScrollPane scrollPane = new JScrollPane();
        scrollPane.setViewportView(messagesTree);

        layout.setHorizontalGroup(layout.createSequentialGroup().addComponent(scrollPane));
        layout.setVerticalGroup(layout.createSequentialGroup().addComponent(scrollPane));
    }

    private void copyTree(SiteNode from, SiteNode to) {
        for (int i = 0; i < from.getChildCount(); i++) {
            SiteNode child = (SiteNode) from.getChildAt(i);
            SiteNode copy = new SiteNode(null, HistoryReference.TYPE_PROXIED, child.getNodeName());
            copy.setUserObject(child);
            to.add(copy);
            copyTree(child, copy);
        }
    }

    @Override
    public JPanel getPanel() {
        return panel;
    }

    @Override
    public boolean validate() {
        SiteNode node = (SiteNode) messagesTree.getLastSelectedPathComponent();
        if (node != null && node.getParent() != null) {
            try {
                selectedHttpMessage =
                        ((SiteNode) node.getUserObject()).getHistoryReference().getHttpMessage();
                return true;
            } catch (HttpMalformedHeaderException | DatabaseException e) {
                LOGGER.error("Failed to read the message: ", e);
                JOptionPane.showMessageDialog(
                        null,
                        Constant.messages.getString(
                                "fuzz.httpfuzzer.select.message.dialogue.error.dialog.message"),
                        Constant.messages.getString(
                                "fuzz.httpfuzzer.select.message.dialogue.error.dialog.title"),
                        JOptionPane.INFORMATION_MESSAGE);
                messagesTree.requestFocusInWindow();
                return false;
            }
        }

        JOptionPane.showMessageDialog(
                null,
                Constant.messages.getString(
                        "fuzz.httpfuzzer.select.message.dialogue.validation.dialog.message"),
                Constant.messages.getString(
                        "fuzz.httpfuzzer.select.message.dialogue.validation.dialog.title"),
                JOptionPane.INFORMATION_MESSAGE);
        messagesTree.requestFocusInWindow();
        return false;
    }

    @Override
    public HttpMessage getSelectedMessage() {
        return selectedHttpMessage;
    }

    @Override
    public void clear() {
        selectedHttpMessage = null;
    }

    @Override
    public String getHelpTarget() {
        // THC add help...
        return null;
    }
}
