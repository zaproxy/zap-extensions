package org.zaproxy.zap.extension.foxhound.ui;

import org.jdesktop.swingx.JXTreeTable;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.AbstractPanel;
import org.zaproxy.zap.extension.foxhound.ExtensionFoxhound;
import org.zaproxy.zap.view.LayoutHelper;

import javax.swing.ImageIcon;
import javax.swing.JScrollPane;
import javax.swing.tree.DefaultMutableTreeNode;
import java.awt.GridBagLayout;

import static org.zaproxy.zap.extension.foxhound.config.FoxhoundConstants.FOXHOUND_16;

@SuppressWarnings("serial")
public class FoxhoundPanel extends AbstractPanel {
    private static final long serialVersionUID = 7L;
    public static final String FOXHOUND_PANEL_NAME = "Foxhound";

    private ExtensionFoxhound extension = null;
    private JScrollPane taintFlowScrollPane;
    private JXTreeTable tree;
    private TaintFlowTreeModel treeModel;

    public FoxhoundPanel(ExtensionFoxhound extension) {
        super();
        this.extension = extension;
        this.initialize();
    }

    private void initialize() {
        this.setName(Constant.messages.getString("foxhound.panel.title"));
        this.setIcon(
                new ImageIcon(
                        FoxhoundPanel.class.getResource(FOXHOUND_16))); // 'flag' icon

        this.setLayout(new GridBagLayout());

        this.add(this.getTaintFlowScrollPane(), LayoutHelper.getGBC(0, 0, 1, 1.0));

        this.setShowByDefault(true);

        extension.getTaintStore().registerEventListener(getTreeModel());
    }

    private TaintFlowTreeModel getTreeModel() {
        if (treeModel == null) {
            treeModel = new TaintFlowTreeModel(new DefaultMutableTreeNode("TaintFlow"));
        }
        return treeModel;
    }

    private JScrollPane getTaintFlowScrollPane() {
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

}

