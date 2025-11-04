package org.zaproxy.zap.extension.foxhound.ui;

import org.zaproxy.zap.extension.foxhound.taint.TaintInfo;
import org.zaproxy.zap.extension.foxhound.taint.TaintOperation;
import org.zaproxy.zap.extension.foxhound.taint.TaintRange;

import javax.swing.JTree;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeCellRenderer;
import java.awt.Color;
import java.awt.Component;

public class TaintFlowCellRenderer  extends DefaultTreeCellRenderer {

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
            setText(op.getOperation());
        }

        return this;
    }
}
