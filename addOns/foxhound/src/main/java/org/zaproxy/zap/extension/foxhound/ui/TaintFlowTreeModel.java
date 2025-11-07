package org.zaproxy.zap.extension.foxhound.ui;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jdesktop.swingx.treetable.AbstractTreeTableModel;
import org.jdesktop.swingx.treetable.TreeTableModel;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.foxhound.taint.TaintInfo;
import org.zaproxy.zap.extension.foxhound.taint.TaintLocation;
import org.zaproxy.zap.extension.foxhound.taint.TaintOperation;
import org.zaproxy.zap.extension.foxhound.taint.TaintRange;
import org.zaproxy.zap.extension.foxhound.utils.StringUtils;
import org.zaproxy.zap.utils.ThreadUtils;

import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import java.awt.EventQueue;
import java.io.Serial;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class TaintFlowTreeModel extends DefaultTreeModel implements TreeTableModel {

    @Serial
    private static final long serialVersionUID = 1L;

    private static final Logger LOGGER = LogManager.getLogger(TaintFlowTreeModel.class);

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
        COLUMN_INFO.add(new ColumnInfo("foxhound.panel.table.header.id", int.class));
        COLUMN_INFO.add(new ColumnInfo("foxhound.panel.table.header.filename", String.class));
        COLUMN_INFO.add(new ColumnInfo("foxhound.panel.table.header.treecontrol", String.class)); // The tree control
        COLUMN_INFO.add(new ColumnInfo("foxhound.panel.table.header.filename", String.class));
        COLUMN_INFO.add(new ColumnInfo("foxhound.panel.table.header.timestamp", LocalDateTime.class));
        COLUMN_INFO.add(new ColumnInfo("foxhound.panel.table.header.function", String.class));
        COLUMN_INFO.add(new ColumnInfo("foxhound.panel.table.header.line", int.class));
        COLUMN_INFO.add(new ColumnInfo("foxhound.panel.table.header.pos", int.class));
        COLUMN_INFO.add(new ColumnInfo("foxhound.panel.table.header.scriptLine", int.class));
        COLUMN_INFO.add(new ColumnInfo("foxhound.panel.table.header.flow", String.class));
        COLUMN_INFO.add(new ColumnInfo("foxhound.panel.table.header.string", String.class));
        COLUMN_INFO.add(new ColumnInfo("foxhound.panel.table.header.url", String.class));
        COLUMN_INFO.add(new ColumnInfo("foxhound.panel.table.header.from", int.class));
        COLUMN_INFO.add(new ColumnInfo("foxhound.panel.table.header.to", int.class));
        COLUMN_INFO.add(new ColumnInfo("foxhound.panel.table.header.source", String.class));
        COLUMN_INFO.add(new ColumnInfo("foxhound.panel.table.header.sink", String.class));
    };

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
                DefaultMutableTreeNode stringNode = new DefaultMutableTreeNode(
                        StringUtils.limitedSubstring(taintedString, lastRangeEnd, range.getBegin()));
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
        if ((!ranges.isEmpty()) && (ranges.getLast().getEnd() < taintedString.length())) {
            DefaultMutableTreeNode stringNode = new DefaultMutableTreeNode(
                    StringUtils.limitedSubstring(taintedString, ranges.getLast().getEnd(), taintedString.length()));
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
        return 1;
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
                    return location.getFilename();
                case "foxhound.panel.table.header.url":
                    return taintInfo.getLocation();
                case "foxhound.panel.table.header.flow":
                    return taintInfo.getSourceSinkLabel();
                case "foxhound.panel.table.header.from":
                    return "";
                case "foxhound.panel.table.header.to":
                    return "";
                case "foxhound.panel.table.header.source":
                    return String.join(", ", taintInfo.getSources().stream().map(TaintOperation::getOperation).toList());
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
                    return String.join(", ", range.getSources().stream().map(TaintOperation::getOperation).toList());
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
