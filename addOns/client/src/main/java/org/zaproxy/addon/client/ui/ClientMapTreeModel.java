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

import java.util.IdentityHashMap;
import java.util.Map;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import org.zaproxy.addon.client.internal.ClientMap;
import org.zaproxy.addon.client.internal.ClientMapListener;
import org.zaproxy.addon.client.internal.ClientNode;
import org.zaproxy.addon.client.internal.ClientSideComponent;
import org.zaproxy.zap.utils.ThreadUtils;

/**
 * A tree model that mirrors a {@link ClientMap}, to be used by the UI.
 *
 * <p>The map can be changed from any thread, the changes are applied to this model, and thus the
 * tree, in the EDT. The user object of the nodes of this model are the nodes of the map.
 */
@SuppressWarnings("serial")
class ClientMapTreeModel extends DefaultTreeModel implements ClientMapListener {

    private static final long serialVersionUID = 1L;

    // Only accessed in the EDT.
    private final transient Map<ClientNode, DefaultMutableTreeNode> nodes = new IdentityHashMap<>();

    ClientMapTreeModel(ClientMap clientMap) {
        super(new DefaultMutableTreeNode(clientMap.getRoot()));
        // Register first, so no change is missed, the events are handled after this.
        clientMap.addListener(this);
        ThreadUtils.invokeLater(() -> populate(clientMap.getRoot(), (DefaultMutableTreeNode) root));
    }

    /**
     * Gets the map node from the given tree node.
     *
     * @param treeNode the node of the tree, might be {@code null}.
     * @return the map node, or {@code null} if none.
     */
    static ClientNode toClientNode(Object treeNode) {
        if (treeNode instanceof DefaultMutableTreeNode node
                && node.getUserObject() instanceof ClientNode clientNode) {
            return clientNode;
        }
        return null;
    }

    private void populate(ClientNode node, DefaultMutableTreeNode treeNode) {
        nodes.put(node, treeNode);
        for (int i = 0; i < node.getChildCount(); i++) {
            ClientNode child = node.getChildAt(i);
            if (nodes.containsKey(child)) {
                continue;
            }
            DefaultMutableTreeNode childTreeNode = new DefaultMutableTreeNode(child);
            treeNode.add(childTreeNode);
            populate(child, childTreeNode);
        }
        nodeStructureChanged(treeNode);
    }

    @Override
    public void nodeAdded(String url, int depth, int siblings, int source) {
        // Nothing to do, the node is handled once inserted.
    }

    @Override
    public void componentAdded(ClientSideComponent component, int depth, int siblings, int source) {
        // Nothing to do, the node changed is handled separately.
    }

    @Override
    public void nodeInserted(ClientNode parent, ClientNode node, int index) {
        ThreadUtils.invokeLater(
                () -> {
                    DefaultMutableTreeNode parentTreeNode = nodes.get(parent);
                    if (parentTreeNode == null || nodes.containsKey(node)) {
                        return;
                    }
                    DefaultMutableTreeNode treeNode = new DefaultMutableTreeNode(node);
                    nodes.put(node, treeNode);
                    insertNodeInto(
                            treeNode,
                            parentTreeNode,
                            Math.min(index, parentTreeNode.getChildCount()));
                    if (parentTreeNode.getChildCount() == 1) {
                        // No longer a leaf, update its icon.
                        nodeChanged(parentTreeNode);
                    }
                });
    }

    @Override
    public void nodeChanged(ClientNode node) {
        ThreadUtils.invokeLater(
                () -> {
                    DefaultMutableTreeNode treeNode = nodes.get(node);
                    if (treeNode != null) {
                        nodeChanged(treeNode);
                    }
                });
    }

    @Override
    public void nodeRemoved(ClientNode node) {
        ThreadUtils.invokeLater(
                () -> {
                    DefaultMutableTreeNode treeNode = nodes.get(node);
                    if (treeNode == null || treeNode.getParent() == null) {
                        return;
                    }
                    forget(treeNode);
                    removeNodeFromParent(treeNode);
                });
    }

    @Override
    public void mapCleared() {
        ThreadUtils.invokeLater(
                () -> {
                    DefaultMutableTreeNode rootTreeNode = (DefaultMutableTreeNode) root;
                    rootTreeNode.removeAllChildren();
                    nodes.clear();
                    nodes.put((ClientNode) rootTreeNode.getUserObject(), rootTreeNode);
                    nodeStructureChanged(rootTreeNode);
                });
    }

    private void forget(DefaultMutableTreeNode treeNode) {
        nodes.remove((ClientNode) treeNode.getUserObject());
        for (int i = 0; i < treeNode.getChildCount(); i++) {
            forget((DefaultMutableTreeNode) treeNode.getChildAt(i));
        }
    }
}
