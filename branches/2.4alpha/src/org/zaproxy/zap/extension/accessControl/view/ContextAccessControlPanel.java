package org.zaproxy.zap.extension.accessControl.view;

import static org.zaproxy.zap.extension.accessControl.widgets.UriNodeIcons.FOLDER_CLOSED_ICON;
import static org.zaproxy.zap.extension.accessControl.widgets.UriNodeIcons.FOLDER_CLOSED_ICON_CHECK;
import static org.zaproxy.zap.extension.accessControl.widgets.UriNodeIcons.FOLDER_CLOSED_ICON_CROSS;
import static org.zaproxy.zap.extension.accessControl.widgets.UriNodeIcons.FOLDER_OPEN_ICON;
import static org.zaproxy.zap.extension.accessControl.widgets.UriNodeIcons.FOLDER_OPEN_ICON_CHECK;
import static org.zaproxy.zap.extension.accessControl.widgets.UriNodeIcons.FOLDER_OPEN_ICON_CROSS;
import static org.zaproxy.zap.extension.accessControl.widgets.UriNodeIcons.LEAF_ICON;
import static org.zaproxy.zap.extension.accessControl.widgets.UriNodeIcons.LEAF_ICON_CHECK;
import static org.zaproxy.zap.extension.accessControl.widgets.UriNodeIcons.LEAF_ICON_CROSS;
import static org.zaproxy.zap.extension.accessControl.widgets.UriNodeIcons.ROOT_ICON;

import java.awt.Color;
import java.awt.Component;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.swing.BorderFactory;
import javax.swing.DefaultCellEditor;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JScrollPane;
import javax.swing.JTree;
import javax.swing.tree.DefaultTreeCellRenderer;

import org.apache.log4j.Logger;
import org.jdesktop.swingx.JXTreeTable;
import org.jdesktop.swingx.treetable.DefaultTreeTableModel;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.model.SiteNode;
import org.zaproxy.zap.extension.accessControl.AccessRule;
import org.zaproxy.zap.extension.accessControl.ContextAccessRulesManager;
import org.zaproxy.zap.extension.accessControl.ExtensionAccessControl;
import org.zaproxy.zap.extension.accessControl.widgets.UriNode;
import org.zaproxy.zap.extension.accessControl.widgets.UriNodeTreeModel;
import org.zaproxy.zap.extension.users.ExtensionUserManagement;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.users.User;
import org.zaproxy.zap.view.AbstractContextPropertiesPanel;
import org.zaproxy.zap.view.LayoutHelper;
import org.zaproxy.zap.view.widgets.ContextPanelUsersSelectComboBox;

public class ContextAccessControlPanel extends AbstractContextPropertiesPanel {

	private static final Logger log = Logger.getLogger(ContextAccessControlPanel.class);
	private static final long serialVersionUID = -7569788230643264454L;

	private static final String PANEL_NAME = Constant.messages.getString("accessControl.contextPanel.title");

	private ExtensionAccessControl extension;
	private JXTreeTable tree;
	private JScrollPane treePane;
	private UriNodeTreeModel treeModel;
	private Map<Integer, ContextUserAccessControlModel> userModels;
	private int selectedUserId = 0;
	private ContextAccessRulesManager tempRulesManager;
	private ContextPanelUsersSelectComboBox usersComboBox;
	private static ExtensionUserManagement usersExtension;

	public ContextAccessControlPanel(ExtensionAccessControl extensionAccessControl, int contextId) {
		super(contextId);
		this.extension = extensionAccessControl;
		this.userModels = new HashMap<>();
		this.selectedUserId = 0;
		initializeView();
	}

	/**
	 * Initialize the panel.
	 */
	private void initializeView() {
		this.setName(getContextIndex() + ": " + PANEL_NAME);
		this.setLayout(new GridBagLayout());

		this.add(new JLabel(Constant.messages
				.getHtmlWrappedString("accessControl.contextPanel.label.description")), LayoutHelper.getGBC(
				0, 0, 2, 1.0D, new Insets(0, 0, 10, 0)));

		// The user selection box
		this.add(new JLabel(Constant.messages.getString("accessControl.contextPanel.label.user")),
				LayoutHelper.getGBC(0, 1, 1, 0.0D));
		this.add(getUsersComboBox(), LayoutHelper.getGBC(1, 1, 1, 1.0D, new Insets(0, 5, 0, 5)));

		// The site tree for the access rules of each context
		this.add(getContextSiteTreePane(), LayoutHelper.getGBC(0, 2, 2, 1.0D, 1.0D, GridBagConstraints.BOTH,
				new Insets(10, 0, 0, 5)));
	}

	private JScrollPane getContextSiteTreePane() {
		if (treePane == null) {
			// Initialize the tree and pane to display it
			tree = new JXTreeTable();
			treePane = new JScrollPane(tree);
			treePane.setBorder(BorderFactory.createEtchedBorder(javax.swing.border.EtchedBorder.RAISED));

			// Set up the tree accordingly
			tree.setShowsRootHandles(true);
			tree.setRootVisible(true);
			tree.setTreeCellRenderer(new AccessRuleNodeCellRenderer());

			// Set up the editor for the Access Rules so it displays as a combo-box
			JComboBox<AccessRule> comboBox = new JComboBox<>(new AccessRule[] { AccessRule.ALLOWED,
					AccessRule.DENIED, AccessRule.INHERIT });
			tree.setDefaultEditor(AccessRule.class, new DefaultCellEditor(comboBox));

			// Initialize the tree
			treeModel = new UriNodeTreeModel(new UriNode("Sites", null));
		}
		return treePane;
	}

	private ContextUserAccessControlModel getUserModel(int userId) {
		ContextUserAccessControlModel model = userModels.get(userId);
		if (model == null) {
			model = new ContextUserAccessControlModel(userId, treeModel, tempRulesManager);
			userModels.put(userId, model);
		}
		// Make sure the model has the proper rules manager
		model.setRulesManager(tempRulesManager);
		return model;
	}

	private ContextPanelUsersSelectComboBox getUsersComboBox() {
		if (usersComboBox == null) {
			usersComboBox = new ContextPanelUsersSelectComboBox(getContextIndex());
			usersComboBox.addActionListener(new ActionListener() {

				@Override
				public void actionPerformed(ActionEvent e) {
					User selectedUser = usersComboBox.getSelectedUser();
					if (selectedUser != null) {
						selectedUserId = selectedUser.getId();
						tree.setVisible(true);
						tree.setTreeTableModel(getUserModel(selectedUserId));
						tree.expandAll();
					} else {
						tree.setVisible(false);
						tree.setTreeTableModel(new DefaultTreeTableModel());
						tree.expandAll();
					}
				}
			});
		}
		return usersComboBox;
	}

	public static String getPanelName(int contextId) {
		// Panel names have to be unique, so prefix with the context id
		return contextId + ": " + PANEL_NAME;
	}

	@Override
	public void initContextData(Session session, Context uiSharedContext) {
		// Re-generate the context tree so we are up-to-date
		((UriNode) treeModel.getRoot()).removeAllChildren();
		loadTree(session, uiSharedContext);

		// Clone the Access Rules Manager so we can support canceling any changes
		ContextAccessRulesManager originalManager = extension.getUserAccessRules(uiSharedContext.getIndex());
		this.tempRulesManager = new ContextAccessRulesManager(uiSharedContext, originalManager);
		// And make sure we set the new rules manager on the existing table model
		if (tree.getTreeTableModel() instanceof ContextUserAccessControlModel) {
			ContextUserAccessControlModel selectedModel = (ContextUserAccessControlModel) tree
					.getTreeTableModel();
			selectedModel.setRulesManager(tempRulesManager);
		}

		// Expand the tree
		tree.expandAll();
	}

	@Override
	public void validateContextData(Session session) throws Exception {
		// Nothing to validate

	}

	@Override
	public void saveTemporaryContextData(Context uiSharedContext) {
		// Nothing to save as the data is already saved in the 'tempRulesManager'

	}

	@Override
	public void saveContextData(Session session) throws Exception {
		List<User> users = getUsersManagementExtension().getUIConfiguredUsers(getContextIndex());
		extension.getUserAccessRules(getContextIndex()).copyRulesFrom(tempRulesManager, users);
	}

	@Override
	public String getHelpIndex() {
		// TODO Auto-generated method stub
		return null;
	}

	private static ExtensionUserManagement getUsersManagementExtension() {
		if (usersExtension == null) {
			usersExtension = (ExtensionUserManagement) Control.getSingleton().getExtensionLoader()
					.getExtension(ExtensionUserManagement.class);
			if (usersExtension == null)
				throw new IllegalStateException(
						"The required Users Management extension could not be loaded.");
		}
		return usersExtension;
	}

	private void loadTree(Session session, Context context) {
		log.debug("Reloading tree for context: " + context.getIndex());
		List<SiteNode> contextNodes = session.getNodesInContextFromSiteTree(context);
		for (SiteNode node : contextNodes) {
			HistoryReference ref = node.getHistoryReference();
			if (ref != null)
				treeModel.addPath(context, ref.getURI(), ref.getMethod());
		}
		treeModel.reload();
	}

	private static final Color COLOR_DENIED = Color.RED;
	private static final Color COLOR_ALLOWED = new Color(31, 131, 31);
	private static final Color COLOR_UNKNOWN = new Color(76, 76, 76);
	private static final Color COLOR_DENIED_FOCUS = new Color(255, 195, 195);
	private static final Color COLOR_ALLOWED_FOCUS = new Color(195, 255, 195);
	private static final Color COLOR_UNKNOWN_FOCUS = new Color(220, 220, 220);

	/**
	 * A custom cell renderer used for the tree of access rules that sets custom colors and icons
	 * depending on the node and the inferred rule.
	 */
	private class AccessRuleNodeCellRenderer extends DefaultTreeCellRenderer {

		private static final long serialVersionUID = 5863120297397993899L;

		@Override
		public Component getTreeCellRendererComponent(JTree tree, Object value, boolean sel,
				boolean expanded, boolean leaf, int row, boolean hasFocus) {

			super.getTreeCellRendererComponent(tree, value, sel, expanded, leaf, row, hasFocus);

			if (!(value instanceof UriNode))
				return this;

			// Depending on the state of the node and the infer rule, set the icon and color
			// accordingly
			UriNode node = (UriNode) value;
			if (node != null) {
				if (node.isRoot()) {
					setIcon(ROOT_ICON); // 'World' icon
				} else {
					// Infer the rule so we can draw accordinglyF
					AccessRule rule = tempRulesManager.inferRule((UriNode) treeModel.getRoot(),
							selectedUserId, node);
					switch (rule) {
					case ALLOWED:
						// Text color
						if (sel)
							this.setForeground(COLOR_ALLOWED_FOCUS);
						else
							this.setForeground(COLOR_ALLOWED);

						// Icon
						if (leaf)
							setIcon(LEAF_ICON_CHECK);
						else if (expanded)
							setIcon(FOLDER_OPEN_ICON_CHECK);
						else
							setIcon(FOLDER_CLOSED_ICON_CHECK);
						break;
					case DENIED:
						// Text color
						if (sel)
							this.setForeground(COLOR_DENIED_FOCUS);
						else
							this.setForeground(COLOR_DENIED);

						// Icon
						if (leaf)
							setIcon(LEAF_ICON_CROSS);
						else if (expanded)
							setIcon(FOLDER_OPEN_ICON_CROSS);
						else
							setIcon(FOLDER_CLOSED_ICON_CROSS);
						break;
					default:
						// Text color
						if (sel)
							this.setForeground(COLOR_UNKNOWN_FOCUS);
						else
							this.setForeground(COLOR_UNKNOWN);

						// Icon
						if (leaf)
							setIcon(LEAF_ICON);
						else if (expanded)
							setIcon(FOLDER_OPEN_ICON);
						else
							setIcon(FOLDER_CLOSED_ICON);
						break;
					}
				}
				// Set the text as the node name
				setText(node.getNodeName());
			}
			return this;
		}
	}

}
