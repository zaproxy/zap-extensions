package org.zaproxy.zap.extension.foxhound.ui;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jdesktop.swingx.JXTreeTable;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.foxhound.taint.HttpMessageFinder;
import org.zaproxy.zap.extension.foxhound.taint.Range;
import org.zaproxy.zap.extension.foxhound.taint.TaintLocation;
import org.zaproxy.zap.extension.foxhound.taint.TaintLocationProvider;
import org.zaproxy.zap.extension.httppanel.HttpPanel;
import org.zaproxy.zap.extension.search.SearchMatch;
import org.zaproxy.zap.utils.ThreadUtils;

import javax.swing.event.TreeSelectionEvent;
import javax.swing.event.TreeSelectionListener;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;
import javax.swing.tree.DefaultMutableTreeNode;
import java.io.Serial;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

public class TaintFlowTreeTable extends JXTreeTable  {

    @Serial
    private static final long serialVersionUID = 1L;

    private static final Logger LOGGER = LogManager.getLogger(TaintFlowTreeTable.class);

    private TaintFlowTreeModel treeModel;
    private final DisplayMessageOnSelectionValueChange defaultSelectionListener;

    public TaintFlowTreeTable() {
        super();
        setColumnControlVisible(true);
        setTreeTableModel(getTreeModel());
        setTreeCellRenderer(new TaintFlowCellRenderer());
        TableRowSorter<TableModel> sorter = new TableRowSorter<TableModel>(getModel());
        setRowSorter(sorter);

        this.defaultSelectionListener = new DisplayMessageOnSelectionValueChange();
        this.getTreeSelectionModel().addTreeSelectionListener(defaultSelectionListener);

    }

    public TaintFlowTreeModel getTreeModel() {
        if (treeModel == null) {
            treeModel = new TaintFlowTreeModel(new DefaultMutableTreeNode("TaintFlow"));
        }
        return treeModel;
    }

    protected DisplayMessageOnSelectionValueChange getDefaultSelectionListener() {
        return defaultSelectionListener;
    }

    protected class DisplayMessageOnSelectionValueChange implements TreeSelectionListener, Serializable {

        @Serial
        private static final long serialVersionUID = 1L;

        private boolean enabled;

        public DisplayMessageOnSelectionValueChange() {
            enabled = true;
        }


        @Override
        public void valueChanged(final TreeSelectionEvent evt) {

            if (!enabled) {
                return;
            }

            ThreadUtils.invokeLater(() -> {
                Object obj = null;
                Object node = evt.getPath().getLastPathComponent();
                if (node instanceof DefaultMutableTreeNode) {
                    obj = ((DefaultMutableTreeNode) node).getUserObject();
                }
                HttpMessage msg = null;
                if (obj != null) {
                    if (obj instanceof TaintLocationProvider provider) {
                        String url = provider.getLocation().getFilename();
                        TaintLocation location = provider.getLocation();
                        msg = HttpMessageFinder.findHttpMessage(url);
                        if (msg != null) {
                            // Display the message and highlight the taint location
                            View.getSingleton().displayMessage(msg);
                            HttpPanel responsePanel = View.getSingleton().getResponsePanel();
                            String body = msg.getResponseBody().toString();
                            Range sourceRange = location.getCodeSpan(body);
                            SearchMatch sm = new SearchMatch(
                                    msg,
                                    SearchMatch.Location.RESPONSE_BODY,
                                    sourceRange.getBegin(), sourceRange.getEnd()
                            );
                            LOGGER.info("TaintLocation: {}:{} to {}:{}", location.getLine(), location.getPos(), location.getNextLine(), location.getNextPos());
                            LOGGER.info("TreeSelectionEvent found URL: {} with message {} highlighting {} string {}", url, msg, sm, location.getCodeForEvidence(body));
                            responsePanel.highlightBody(sm);
                            responsePanel.setTabFocus();
                        }
                    }
                }
            });

            if (isFocusOwner()) {
                requestFocusInWindow();
            }

        }

    }


}
