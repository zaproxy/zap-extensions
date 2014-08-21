package org.zaproxy.zap.extension.accessControl.view;

import java.util.Map;

import javax.swing.tree.DefaultTreeModel;

import org.jdesktop.swingx.treetable.TreeTableModel;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.accessControl.AccessRule;
import org.zaproxy.zap.extension.accessControl.ContextAccessRulesManager;
import org.zaproxy.zap.extension.accessControl.widgets.SiteTreeNode;

public class ContextUserAccessRulesModel extends DefaultTreeModel implements TreeTableModel {

	private static final long serialVersionUID = -1876199137051156699L;

	private static final int COLUMN_INDEX_NODE = 0;
	private static final int COLUMN_INDEX_RULE = 1;

	private static final String COLUMN_NAME_NODE = "Node";
	private static final String COLUMN_NAME_RULE = "Rule";

	private int userId;
	private ContextAccessRulesManager rulesManager;
	private SiteTreeNode hangingNodesRoot;
	private SiteTreeNode root;

	public ContextUserAccessRulesModel(int userId, ContextAccessRulesManager rulesManager) {
		super(rulesManager.getContextSiteTree().getRoot());
		this.rulesManager = rulesManager;
		this.userId = userId;
		this.root = rulesManager.getContextSiteTree().getRoot();
		prepareHangingRules(rulesManager.computeHangingRules(userId));
	}

	private void prepareHangingRules(Map<SiteTreeNode, AccessRule> hangingRules) {
		if (hangingRules == null || hangingRules.isEmpty())
			return;

		hangingNodesRoot = new SiteTreeNode(Constant.messages.getString("accessControl.contextTree.hanging"),
				null);
		for (SiteTreeNode node : hangingRules.keySet()) {
			hangingNodesRoot.add(node);
		}
		root.add(hangingNodesRoot);
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
		SiteTreeNode uriNode = (SiteTreeNode) node;
		switch (column) {
		case COLUMN_INDEX_NODE:
			return uriNode.getNodeName();
		case COLUMN_INDEX_RULE:
			// For the root return
			return (uriNode.isRoot() || uriNode == hangingNodesRoot) ? null : rulesManager.getDefinedRule(
					userId, uriNode).toString();
		}
		return null;
	}

	@Override
	public Object getChild(Object parent, int index) {
		SiteTreeNode node = (SiteTreeNode) parent;
		return node.getChildAt(index);
	}

	@Override
	public int getChildCount(Object parent) {
		SiteTreeNode node = (SiteTreeNode) parent;
		return node.getChildCount();
	}

	@Override
	public int getIndexOfChild(Object parent, Object child) {
		SiteTreeNode node = (SiteTreeNode) parent;
		return node.getIndex((SiteTreeNode) child);
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
		return column == COLUMN_INDEX_RULE && !((SiteTreeNode) node).isRoot() && (node != hangingNodesRoot);
	}

	@Override
	public int getHierarchicalColumn() {
		return 0;
	}

	@Override
	public void setValueAt(Object value, Object node, int column) {
		rulesManager.addRule(userId, (SiteTreeNode) node, (AccessRule) value);
	}

}
