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
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.List;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jdesktop.swingx.treetable.TreeTableModel;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.foxhound.taint.TaintInfo;
import org.zaproxy.zap.extension.foxhound.taint.TaintLocation;
import org.zaproxy.zap.extension.foxhound.taint.TaintOperation;
import org.zaproxy.zap.extension.foxhound.taint.TaintRange;
import org.zaproxy.zap.extension.foxhound.utils.StringUtils;

public class TaintFlowTreeModel extends DefaultTreeModel implements TreeTableModel {

    @Serial private static final long serialVersionUID = 1L;

    private static final Logger LOGGER = LogManager.getLogger(TaintFlowTreeModel.class);

    private ArrayList<TaintInfo> envVars = new ArrayList<>();

    public TaintFlowTreeModel(DefaultMutableTreeNode root) {
        super(root);
    }

    private static class ColumnInfo {

        private String key;
        private String columnName;
        private Class<?> clazz;

        public ColumnInfo(String key, Class<?> clazz) {
            this.columnName = Constant.messages.getString(key);
            this.clazz = clazz;
            this.key = key;
        }

        public String getKey() {
            return key;
        }

        public String getColumnName() {
            return columnName;
        }

        public Class<?> getClazz() {
            return clazz;
        }
    }

    private static final List<ColumnInfo> COLUMN_INFO = new ArrayList<>();

    static {
        COLUMN_INFO.add(
                new ColumnInfo(
                        "foxhound.panel.table.header.treecontrol",
                        String.class)); // The tree control
        COLUMN_INFO.add(new ColumnInfo("foxhound.panel.table.header.filename", String.class));
        COLUMN_INFO.add(new ColumnInfo("foxhound.panel.table.header.line", int.class));
        COLUMN_INFO.add(new ColumnInfo("foxhound.panel.table.header.pos", int.class));
    }
    ;

    private static final int COLUMN_COUNT = COLUMN_INFO.size();

    @Override
    public DefaultMutableTreeNode getRoot() {
        return (DefaultMutableTreeNode) super.getRoot();
    }

    public void taintInfoAdded(TaintInfo info) {
        DefaultMutableTreeNode node = new DefaultMutableTreeNode(info);
        this.getRoot().add(node);
        // Add the different parts of the taint info
        String taintedString = info.getStr();
        List<TaintRange> ranges = info.getTaintRanges();

        int lastRangeEnd = 0;
        for (TaintRange range : ranges) {
            if (range.getBegin() > lastRangeEnd) {
                DefaultMutableTreeNode stringNode =
                        new DefaultMutableTreeNode(
                                StringUtils.limitedSubstring(
                                        taintedString, lastRangeEnd, range.getBegin()));
                node.add(stringNode);
            }

            DefaultMutableTreeNode rangeNode = new DefaultMutableTreeNode(range);
            node.add(rangeNode);
            for (TaintOperation op : range.getFlow()) {
                DefaultMutableTreeNode flowNode = new DefaultMutableTreeNode(op);
                rangeNode.add(flowNode);
            }
            lastRangeEnd = range.getEnd();
        }

        // Add final untainted string fragment
        if ((!ranges.isEmpty())
                && (ranges.get(ranges.size() - 1).getEnd() < taintedString.length())) {
            DefaultMutableTreeNode stringNode =
                    new DefaultMutableTreeNode(
                            StringUtils.limitedSubstring(
                                    taintedString,
                                    ranges.get(ranges.size() - 1).getEnd(),
                                    taintedString.length()));
            node.add(stringNode);
        }
        this.fireTreeStructureChanged(this, null, null, null);
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return COLUMN_INFO.get(columnIndex).getClazz();
    }

    @Override
    public int getColumnCount() {
        return COLUMN_COUNT;
    }

    @Override
    public String getColumnName(int column) {
        return COLUMN_INFO.get(column).getColumnName();
    }

    @Override
    public int getHierarchicalColumn() {
        return 0;
    }

    @Override
    public Object getValueAt(Object node, int column) {
        DefaultMutableTreeNode treeNode = (DefaultMutableTreeNode) node;
        if (treeNode.isRoot()) {
            return null;
        }
        Object obj = treeNode.getUserObject();
        String columnKey = COLUMN_INFO.get(column).getKey();
        TaintLocation location = null;
        if (columnKey == null) {
            return "";
        } else if (obj instanceof String s) {
            // NOP but could add later
        } else if (obj instanceof TaintInfo taintInfo) {
            location = taintInfo.getSink().getLocation();
            switch (columnKey) {
                case "foxhound.panel.table.header.id":
                    return taintInfo.getId();
                case "foxhound.panel.table.header.timestamp":
                    Instant instant = Instant.ofEpochMilli(taintInfo.getTimeStamp());
                    return LocalDateTime.ofInstant(instant, ZoneId.systemDefault());
                case "foxhound.panel.table.header.filename":
                    return taintInfo.getLocationName();
                case "foxhound.panel.table.header.url":
                    return taintInfo.getLocation();
                case "foxhound.panel.table.header.flow":
                    return taintInfo.getSourceSinkLabel();
                case "foxhound.panel.table.header.from":
                    return "";
                case "foxhound.panel.table.header.to":
                    return "";
                case "foxhound.panel.table.header.source":
                    return String.join(
                            ", ",
                            taintInfo.getSources().stream()
                                    .map(TaintOperation::getOperation)
                                    .toList());
                case "foxhound.panel.table.header.sink":
                    return taintInfo.getSink().getOperation();
                case "foxhound.panel.table.header.string":
                    return taintInfo.getStr();
            }
        } else if (obj instanceof TaintRange range) {
            location = range.getSink().getLocation();
            switch (columnKey) {
                case "foxhound.panel.table.header.url":
                    return "";
                case "foxhound.panel.table.header.flow":
                    return range.getSourceSinkLabel();
                case "foxhound.panel.table.header.from":
                    return range.getBegin();
                case "foxhound.panel.table.header.to":
                    return range.getEnd();
                case "foxhound.panel.table.header.source":
                    return String.join(
                            ", ",
                            range.getSources().stream().map(TaintOperation::getOperation).toList());
                case "foxhound.panel.table.header.sink":
                    return range.getSink().getOperation();
                case "foxhound.panel.table.header.string":
                    return range.getStr();
            }
        } else if (obj instanceof TaintOperation op) {
            location = op.getLocation();
            switch (columnKey) {
                case "foxhound.panel.table.header.url":
                    return "";
                case "foxhound.panel.table.header.flow":
                    return op.getOperation();
            }
        }

        if (location != null) {
            switch (columnKey) {
                case "foxhound.panel.table.header.filename":
                    return location.getFilename();
                case "foxhound.panel.table.header.function":
                    return location.getFunction();
                case "foxhound.panel.table.header.line":
                    return location.getLine();
                case "foxhound.panel.table.header.pos":
                    return location.getPos();
                case "foxhound.panel.table.header.scriptLine":
                    return location.getScriptLine();
            }
        }

        return "";
    }

    @Override
    public boolean isCellEditable(Object node, int column) {
        return false;
    }

    @Override
    public void setValueAt(Object value, Object node, int column) {
        // Nothing to do, don't want to edit results
    }

    public void clear() {
        this.getRoot().removeAllChildren();
        this.fireTreeStructureChanged(this, null, null, null);
    }
}
