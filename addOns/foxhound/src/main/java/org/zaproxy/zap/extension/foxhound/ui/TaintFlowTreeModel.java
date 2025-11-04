package org.zaproxy.zap.extension.foxhound.ui;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jdesktop.swingx.treetable.TreeTableModel;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.foxhound.taint.TaintInfo;
import org.zaproxy.zap.extension.foxhound.taint.TaintOperation;
import org.zaproxy.zap.extension.foxhound.taint.TaintRange;
import org.zaproxy.zap.extension.foxhound.taint.TaintStoreEventListener;

import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import java.io.Serial;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class TaintFlowTreeModel extends DefaultTreeModel implements TreeTableModel, TaintStoreEventListener {

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
        COLUMN_INFO.add(new ColumnInfo("foxhound.panel.table.header.treecontrol", String.class)); // The tree control
        COLUMN_INFO.add(new ColumnInfo("foxhound.panel.table.header.url", String.class));
        COLUMN_INFO.add(new ColumnInfo("foxhound.panel.table.header.flow", String.class));
        COLUMN_INFO.add(new ColumnInfo("foxhound.panel.table.header.from", int.class));
        COLUMN_INFO.add(new ColumnInfo("foxhound.panel.table.header.to", int.class));
        COLUMN_INFO.add(new ColumnInfo("foxhound.panel.table.header.source", String.class));
        COLUMN_INFO.add(new ColumnInfo("foxhound.panel.table.header.sink", String.class));
        COLUMN_INFO.add(new ColumnInfo("foxhound.panel.table.header.string", String.class));
    };

    private static final int COLUMN_COUNT = COLUMN_INFO.size();

    @Override
    public DefaultMutableTreeNode getRoot() {
        return (DefaultMutableTreeNode) super.getRoot();
    }

    @Override
    public void taintInfoAdded(TaintInfo info) {
        DefaultMutableTreeNode node = new DefaultMutableTreeNode(info);
        this.getRoot().add(node);
        // Add the different parts of the taint info
        for (TaintRange range: info.getTaintRanges()) {
            DefaultMutableTreeNode rangeNode = new DefaultMutableTreeNode(range);
            node.add(rangeNode);
            for (TaintOperation op : range.getFlow()) {
                DefaultMutableTreeNode flowNode = new DefaultMutableTreeNode(op);
                rangeNode.add(flowNode);
            }
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
        if (columnKey == null) {
            return "";
        } else if (obj instanceof TaintInfo taintInfo) {
            switch (columnKey) {
                case "foxhound.panel.table.header.url":
                    return taintInfo.getLocation();
                case "foxhound.panel.table.header.flow":
                    return "";
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
            switch (columnKey) {
                case "foxhound.panel.table.header.url":
                    return "";
                case "foxhound.panel.table.header.flow":
                    return "";
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
}
