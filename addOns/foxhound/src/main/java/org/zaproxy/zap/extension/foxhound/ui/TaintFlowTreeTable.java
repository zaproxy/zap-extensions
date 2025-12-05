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

import java.io.Serial;
import java.io.Serializable;
import javax.swing.event.TreeSelectionEvent;
import javax.swing.event.TreeSelectionListener;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;
import javax.swing.tree.DefaultMutableTreeNode;
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

public class TaintFlowTreeTable extends JXTreeTable {

    @Serial private static final long serialVersionUID = 1L;

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

        this.setAutoCreateRowSorter(true);
        this.packAll();
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

    protected class DisplayMessageOnSelectionValueChange
            implements TreeSelectionListener, Serializable {

        @Serial private static final long serialVersionUID = 1L;

        private boolean enabled;

        public DisplayMessageOnSelectionValueChange() {
            enabled = true;
        }

        @Override
        public void valueChanged(final TreeSelectionEvent evt) {

            if (!enabled) {
                return;
            }

            ThreadUtils.invokeLater(
                    () -> {
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
                                    HttpPanel responsePanel =
                                            View.getSingleton().getResponsePanel();
                                    String body = msg.getResponseBody().toString();
                                    Range sourceRange = location.getCodeSpan(body);
                                    SearchMatch sm =
                                            new SearchMatch(
                                                    msg,
                                                    SearchMatch.Location.RESPONSE_BODY,
                                                    sourceRange.getBegin(),
                                                    sourceRange.getEnd());
                                    LOGGER.debug(
                                            "TaintLocation: {}:{} to {}:{}",
                                            location.getLine(),
                                            location.getPos(),
                                            location.getNextLine(),
                                            location.getNextPos());
                                    LOGGER.debug(
                                            "TreeSelectionEvent found URL: {} with message {} highlighting {} string {}",
                                            url,
                                            msg,
                                            sm,
                                            location.getCodeForEvidence(body));
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
