package org.zaproxy.zap.extension.accessControl.view;

import javax.swing.event.TreeModelEvent;
import javax.swing.event.TreeModelListener;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreeNode;

import org.apache.log4j.Logger;
import org.jdesktop.swingx.treetable.TreeTableModel;
import org.zaproxy.zap.extension.accessControl.AccessRule;
import org.zaproxy.zap.extension.accessControl.ContextAccessRulesManager;
import org.zaproxy.zap.extension.accessControl.widgets.UriNode;
import org.zaproxy.zap.extension.accessControl.widgets.UriNodeTreeModel;

public class ContextUserAccessControlModel extends DefaultTreeModel implements TreeTableModel,
		TreeModelListener {

	private static final long serialVersionUID = -1876199137051156699L;

	private static final int COLUMN_INDEX_NODE = 0;
	private static final int COLUMN_INDEX_RULE = 1;

	private static final String COLUMN_NAME_NODE = "Node";
	private static final String COLUMN_NAME_RULE = "Rule";

	private UriNodeTreeModel contextTreeModel;
	private int userId;
	private ContextAccessRulesManager rulesManager;

	public ContextUserAccessControlModel(int userId, UriNodeTreeModel contextTreeModel,
			ContextAccessRulesManager rulesManager) {
		super((TreeNode) contextTreeModel.getRoot());
		this.contextTreeModel = contextTreeModel;
		this.rulesManager = rulesManager;
		this.userId = userId;
		this.contextTreeModel.addTreeModelListener(this);
	}

	public void setRulesManager(ContextAccessRulesManager rulesManager) {
		this.rulesManager = rulesManager;
	}

	@Override
	public int getColumnCount() {
		return 2;
	}

	@Override
	public Object getValueAt(Object node, int column) {
		UriNode uriNode = (UriNode) node;
		switch (column) {
		case COLUMN_INDEX_NODE:
			return uriNode.getNodeName();
		case COLUMN_INDEX_RULE:
			// For the root return
			return uriNode.isRoot() ? null : rulesManager.getDefinedRule(userId, uriNode);
		}
		return null;
	}

	@Override
	public Object getChild(Object parent, int index) {
		return contextTreeModel.getChild(parent, index);
	}

	@Override
	public int getChildCount(Object parent) {
		return contextTreeModel.getChildCount(parent);
	}

	@Override
	public int getIndexOfChild(Object parent, Object child) {
		return contextTreeModel.getIndexOfChild(parent, child);
	}

	@Override
	public Class<?> getColumnClass(int column) {
		switch (column) {
		case COLUMN_INDEX_RULE:
			return AccessRule.class;
		default:
			return String.class;
		}
	}

	@Override
	public String getColumnName(int column) {
		switch (column) {
		case COLUMN_INDEX_NODE:
			return COLUMN_NAME_NODE;
		case COLUMN_INDEX_RULE:
			return COLUMN_NAME_RULE;
		default:
			return "";
		}
	}

	@Override
	public boolean isCellEditable(Object node, int column) {
		return column == COLUMN_INDEX_RULE && !((UriNode) node).isRoot();
	}

	@Override
	public void treeNodesChanged(TreeModelEvent e) {
		this.fireTreeNodesChanged(e.getSource(), e.getPath(), e.getChildIndices(), e.getChildren());
	}

	@Override
	public void treeNodesInserted(TreeModelEvent e) {
		this.fireTreeNodesInserted(e.getSource(), e.getPath(), e.getChildIndices(), e.getChildren());

	}

	@Override
	public void treeNodesRemoved(TreeModelEvent e) {
		this.fireTreeNodesRemoved(e.getSource(), e.getPath(), e.getChildIndices(), e.getChildren());

	}

	@Override
	public void treeStructureChanged(TreeModelEvent e) {
		this.fireTreeStructureChanged(e.getSource(), e.getPath(), e.getChildIndices(), e.getChildren());

	}

	@Override
	public int getHierarchicalColumn() {
		return 0;
	}

	@Override
	public void setValueAt(Object value, Object node, int column) {
		// TODO Auto-generated method stub
		Logger.getLogger(getClass()).info("Setting value to: " + value);
		rulesManager.addRule(userId, (UriNode) node, (AccessRule) value);
	}

}
