/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2013 The ZAP Development Team
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
package org.zaproxy.zap.extension.treetools;

import java.awt.Component;
import java.util.Enumeration;
import javax.swing.JTree;
import javax.swing.tree.TreeNode;
import javax.swing.tree.TreePath;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionPopupMenuItem;

public class PopupMenuTreeTools extends ExtensionPopupMenuItem {

    private static final long serialVersionUID = 1L;
    private JTree sitesTree;

    public PopupMenuTreeTools() {
        super(Constant.messages.getString("treetools.popop"));

        this.addActionListener(
                e -> {
                    TreePath[] paths = sitesTree.getSelectionPaths();
                    for (int i = 0; i < paths.length; i++) {
                        TreePath t = paths[i];
                        if (sitesTree.isExpanded(t)) {
                            expandOrCollapseFromNode(t, false);
                        } else {
                            expandOrCollapseFromNode(t, true);
                        }
                    }
                });
    }

    @SuppressWarnings("unchecked")
    private void expandOrCollapseFromNode(TreePath parent, boolean expand) {
        TreeNode tn = (TreeNode) parent.getLastPathComponent();

        if (tn.getChildCount() > 0) {
            for (Enumeration<? extends TreeNode> e = tn.children(); e.hasMoreElements(); ) {
                TreePath path = parent.pathByAddingChild(e.nextElement());
                expandOrCollapseFromNode(path, expand);
            }
        }

        if (expand) {
            sitesTree.expandPath(parent);
        } else {
            sitesTree.collapsePath(parent);
        }
    }

    @Override
    public boolean isEnableForComponent(Component invoker) {
        if (invoker instanceof JTree) {
            JTree tree = (JTree) invoker;
            if ("treeSite".equals(tree.getName())) {
                this.sitesTree = tree;
                this.setEnabled(true);
                return true;
            }
        }
        return false;
    }

    @Override
    public boolean precedeWithSeparator() {
        return true;
    }

    @Override
    public boolean isSafe() {
        return true;
    }
}
