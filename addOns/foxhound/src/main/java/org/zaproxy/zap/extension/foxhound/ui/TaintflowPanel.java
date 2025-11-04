package org.zaproxy.zap.extension.foxhound.ui;

import org.jdesktop.swingx.JXTreeTable;
import org.parosproxy.paros.extension.AbstractPanel;
import org.zaproxy.zap.eventBus.Event;
import org.zaproxy.zap.eventBus.EventConsumer;

import javax.swing.JScrollPane;
import javax.swing.tree.DefaultMutableTreeNode;
import java.io.Serial;

public class TaintflowPanel extends AbstractPanel implements EventConsumer {

    @Serial
    private static final long serialVersionUID = 1L;

    private JScrollPane taintFlowScrollPane;
    private JXTreeTable tree;
    private TaintFlowTreeModel treeModel;

    private TaintFlowTreeModel getTreeModel() {
        if (treeModel == null) {
            treeModel = new TaintFlowTreeModel(new DefaultMutableTreeNode("TaintFlow"));
        }
        return treeModel;
    }

    private JScrollPane getPlanScrollpane() {
        if (taintFlowScrollPane == null) {
            taintFlowScrollPane = new JScrollPane();
            tree = new JXTreeTable();
            tree.setColumnControlVisible(true);
            tree.setTreeTableModel(getTreeModel());
            tree.setTreeCellRenderer(new TaintFlowCellRenderer());
            taintFlowScrollPane.setViewportView(tree);
        }
        return taintFlowScrollPane;
    }

    @Override
    public void eventReceived(Event event) {

    }
}
