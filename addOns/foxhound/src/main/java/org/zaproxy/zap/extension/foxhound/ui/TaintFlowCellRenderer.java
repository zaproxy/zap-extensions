/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
package org.zaproxy.zap.extension.foxhound.ui;

import java.awt.Color;
import java.awt.Component;
import java.util.Objects;
import javax.swing.JTree;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeCellRenderer;
import org.zaproxy.zap.extension.foxhound.taint.TaintInfo;
import org.zaproxy.zap.extension.foxhound.taint.TaintOperation;
import org.zaproxy.zap.extension.foxhound.taint.TaintRange;

public class TaintFlowCellRenderer extends DefaultTreeCellRenderer {

    private static final long serialVersionUID = 1L;

    @Override
    public Component getTreeCellRendererComponent(
            JTree tree,
            Object value,
            boolean sel,
            boolean expanded,
            boolean leaf,
            int row,
            boolean hasFocus) {

        if (!(value instanceof DefaultMutableTreeNode)) {
            return this;
        }

        DefaultMutableTreeNode node = (DefaultMutableTreeNode) value;
        Object obj = node.getUserObject();
        if (obj == null) {
            return this;
        }

        super.getTreeCellRendererComponent(tree, value, sel, expanded, leaf, row, hasFocus);

        if (node.isRoot()) {
            return this;
        }

        if (obj instanceof String s) {
            setText(s);
            setTextNonSelectionColor(Color.BLACK);
        } else if (obj instanceof TaintInfo taintInfo) {
            setText(taintInfo.getSourceSinkLabel());
        } else if (obj instanceof TaintRange range) {
            setText(range.getStr());
            setTextNonSelectionColor(Color.RED);
        } else if (obj instanceof TaintOperation op) {
            if ((Objects.equals(op.getOperation(), "function")) && (!op.getArguments().isEmpty())) {
                setText(
                        op.getArguments().get(0)
                                + "("
                                + String.join(
                                        ", ",
                                        op.getArguments().subList(1, op.getArguments().size()))
                                + ")");
            } else {
                if (!op.getArguments().isEmpty()) {
                    setText(
                            op.getOperation()
                                    + "('"
                                    + String.join("', '", op.getArguments())
                                    + "')");
                } else {
                    setText(op.getOperation());
                }
            }
        }

        return this;
    }
}
