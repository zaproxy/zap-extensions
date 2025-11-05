package org.zaproxy.zap.extension.foxhound.ui;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jdesktop.swingx.JXTreeTable;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.foxhound.ExtensionFoxhound;
import org.zaproxy.zap.view.LayoutHelper;
import org.zaproxy.zap.view.table.HistoryReferencesTable;
import org.zaproxy.zap.view.table.HistoryReferencesTableEntry;

import javax.swing.ImageIcon;
import javax.swing.JScrollPane;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.tree.DefaultMutableTreeNode;
import java.awt.GridBagLayout;

import static org.zaproxy.zap.extension.foxhound.config.FoxhoundConstants.FOXHOUND_16;

@SuppressWarnings("serial")
public class FoxhoundPanel extends AbstractPanel {
    private static final long serialVersionUID = 7L;
    public static final String FOXHOUND_PANEL_NAME = "Foxhound";
    private static final Logger LOGGER = LogManager.getLogger(FoxhoundPanel.class);

    private ExtensionFoxhound extension = null;
    private JScrollPane taintFlowScrollPane;
    private TaintFlowTreeTable tree;



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

        extension.getTaintStore().registerEventListener(tree.getTreeModel());
    }



    private JScrollPane getTaintFlowScrollPane() {
        if (taintFlowScrollPane == null) {
            taintFlowScrollPane = new JScrollPane();
            tree = new TaintFlowTreeTable();
            taintFlowScrollPane.setViewportView(tree);
        }
        return taintFlowScrollPane;
    }

}

