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
package org.zaproxy.zap.extension.accessControl.widgets;

import java.awt.Component;
import javax.swing.ImageIcon;
import javax.swing.JTree;
import javax.swing.tree.DefaultTreeCellRenderer;

/** Custom renderer for {@link UriNodeTreeModel} to set custom icons. */
public class SiteTreeNodeCellRenderer extends DefaultTreeCellRenderer {

    private static final long serialVersionUID = -6714631438207624613L;

    protected static final ImageIcon ROOT_ICON =
            new ImageIcon(SiteTreeNodeCellRenderer.class.getResource("/resource/icon/16/094.png"));
    protected static final ImageIcon LEAF_ICON =
            new ImageIcon(
                    SiteTreeNodeCellRenderer.class.getResource(
                            "/resource/icon/fugue/document.png"));
    protected static final ImageIcon FOLDER_OPEN_ICON =
            new ImageIcon(
                    SiteTreeNodeCellRenderer.class.getResource(
                            "/resource/icon/fugue/folder-horizontal-open.png"));
    protected static final ImageIcon FOLDER_CLOSED_ICON =
            new ImageIcon(
                    SiteTreeNodeCellRenderer.class.getResource(
                            "/resource/icon/fugue/folder-horizontal.png"));

    /** Sets custom tree node icons. */
    @Override
    public Component getTreeCellRendererComponent(
            JTree tree,
            Object value,
            boolean sel,
            boolean expanded,
            boolean leaf,
            int row,
            boolean hasFocus) {

        super.getTreeCellRendererComponent(tree, value, sel, expanded, leaf, row, hasFocus);

        if (!(value instanceof SiteTreeNode)) {
            return this;
        }

        SiteTreeNode node = (SiteTreeNode) value;
        if (node != null) {
            if (node.isRoot()) {
                setIcon(ROOT_ICON); // 'World' icon
            } else if (leaf) {
                setIcon(LEAF_ICON);
            } else {
                if (expanded) {
                    setIcon(FOLDER_OPEN_ICON);
                } else {
                    setIcon(FOLDER_CLOSED_ICON);
                }
            }
            setText(node.getNodeName());
        }

        return this;
    }
}
