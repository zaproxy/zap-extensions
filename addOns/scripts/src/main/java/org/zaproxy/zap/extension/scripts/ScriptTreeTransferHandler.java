/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
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
package org.zaproxy.zap.extension.scripts;

import java.awt.Component;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.Transferable;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.swing.JComponent;
import javax.swing.JTree;
import javax.swing.TransferHandler;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.TreeNode;
import javax.swing.tree.TreePath;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.zap.extension.script.ScriptNode;

@SuppressWarnings("serial")
public class ScriptTreeTransferHandler extends TransferHandler {

    private static final long serialVersionUID = 1L;
    private static final Logger logger = LogManager.getLogger(ScriptTreeTransferHandler.class);

    DefaultMutableTreeNode[] nodesToRemove;
    DataFlavor nodesFlavor;
    DataFlavor[] flavors = new DataFlavor[1];

    private Map<Class<?>, TransferHandler> htMap = new HashMap<>();

    public void addTransferHandler(Class<?> c, TransferHandler th) {
        logger.debug("addTransferHandler {}", c.getCanonicalName());
        this.htMap.put(c, th);
    }

    public void removeTransferHandler(Class<?> c) {
        logger.debug("removeTransferHandler {}", c.getCanonicalName());
        this.htMap.remove(c);
    }

    private TransferHandler getTransferHandlerForSelection(Component c) {
        if (!(c instanceof JTree)) {
            logger.debug(
                    "getTransferHandlerForSelection not jtree {}", c.getClass().getCanonicalName());
            return null;
        }
        JTree tree = (JTree) c;
        TransferHandler th = null;

        if (tree.getSelectionPaths() == null) {
            return null;
        }

        for (TreePath tp : tree.getSelectionPaths()) {
            if (tp.getLastPathComponent() instanceof ScriptNode) {
                Object uo = ((ScriptNode) tp.getLastPathComponent()).getUserObject();
                if (uo == null) {
                    // One of the selection doesnt have a user object
                    // logger.debug("getTransferHandlerForSelection no user object for {}", tp);
                    return null;
                }
                TransferHandler th2 = this.htMap.get(uo.getClass());
                if (th2 == null) {
                    // No transfer handler, no go
                    return null;
                }
                if (th == null) {
                    th = th2;
                } else if (!th.equals(th2)) {
                    // Different transfer handlers, no go
                    return null;
                }
            }
        }
        // logger.debug("getTransferHandlerForSelection no user objects found");
        return th;
    }

    @Override
    public boolean canImport(TransferHandler.TransferSupport support) {
        logger.debug("canImport {}", support.getComponent().getClass().getCanonicalName());
        TransferHandler th = getTransferHandlerForSelection(support.getComponent());
        if (th != null) {
            return th.canImport(support);
        }

        return false;
    }

    @Override
    protected Transferable createTransferable(JComponent c) {
        JTree tree = (JTree) c;
        TreePath[] paths = tree.getSelectionPaths();
        if (paths != null) {
            // Make up a node array of copies for transfer and
            // another for/of the nodes that will be removed in
            // exportDone after a successful drop.
            List<DefaultMutableTreeNode> copies = new ArrayList<>();
            List<DefaultMutableTreeNode> toRemove = new ArrayList<>();
            DefaultMutableTreeNode node = (DefaultMutableTreeNode) paths[0].getLastPathComponent();
            DefaultMutableTreeNode copy = copy(node);
            copies.add(copy);
            toRemove.add(node);
            for (int i = 1; i < paths.length; i++) {
                DefaultMutableTreeNode next =
                        (DefaultMutableTreeNode) paths[i].getLastPathComponent();
                // Do not allow higher level nodes to be added to list.
                if (next.getLevel() < node.getLevel()) {
                    break;
                } else if (next.getLevel() > node.getLevel()) { // child node
                    copy.add(copy(next));
                    // node already contains child
                } else { // sibling
                    copies.add(copy(next));
                    toRemove.add(next);
                }
            }
            DefaultMutableTreeNode[] nodes =
                    copies.toArray(new DefaultMutableTreeNode[copies.size()]);
            nodesToRemove = toRemove.toArray(new DefaultMutableTreeNode[toRemove.size()]);
            return new NodesTransferable(nodes);
        }
        return null;
    }

    /** Defensive copy used in createTransferable. */
    private DefaultMutableTreeNode copy(TreeNode node) {
        return new DefaultMutableTreeNode(node);
    }

    @Override
    public int getSourceActions(JComponent c) {
        logger.debug("getSourceActions {}", c.getClass().getCanonicalName());
        TransferHandler th = getTransferHandlerForSelection(c);
        if (th != null) {
            return th.getSourceActions(c);
        }
        return TransferHandler.NONE;
    }

    @Override
    public boolean importData(TransferHandler.TransferSupport support) {
        logger.debug("importData {}", support.getComponent().getClass().getCanonicalName());
        TransferHandler th = getTransferHandlerForSelection(support.getComponent());
        if (th != null) {
            return th.importData(support);
        }
        return false;
    }

    public class NodesTransferable implements Transferable {
        DefaultMutableTreeNode[] nodes;

        public NodesTransferable(DefaultMutableTreeNode[] nodes) {
            this.nodes = nodes;
        }

        @Override
        public Object getTransferData(DataFlavor flavor) throws UnsupportedFlavorException {
            if (!isDataFlavorSupported(flavor)) throw new UnsupportedFlavorException(flavor);
            return nodes;
        }

        @Override
        public DataFlavor[] getTransferDataFlavors() {
            return flavors;
        }

        @Override
        public boolean isDataFlavorSupported(DataFlavor flavor) {
            return nodesFlavor.equals(flavor);
        }
    }
}
