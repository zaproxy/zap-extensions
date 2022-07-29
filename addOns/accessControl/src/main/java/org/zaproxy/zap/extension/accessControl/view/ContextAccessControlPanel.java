/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
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
package org.zaproxy.zap.extension.accessControl.view;

import static org.zaproxy.zap.extension.accessControl.ContextAccessRulesManager.UNAUTHENTICATED_USER_ID;
import static org.zaproxy.zap.extension.accessControl.widgets.SiteNodeIcons.FOLDER_CLOSED_ICON;
import static org.zaproxy.zap.extension.accessControl.widgets.SiteNodeIcons.FOLDER_CLOSED_ICON_CHECK;
import static org.zaproxy.zap.extension.accessControl.widgets.SiteNodeIcons.FOLDER_CLOSED_ICON_CROSS;
import static org.zaproxy.zap.extension.accessControl.widgets.SiteNodeIcons.FOLDER_OPEN_ICON;
import static org.zaproxy.zap.extension.accessControl.widgets.SiteNodeIcons.FOLDER_OPEN_ICON_CHECK;
import static org.zaproxy.zap.extension.accessControl.widgets.SiteNodeIcons.FOLDER_OPEN_ICON_CROSS;
import static org.zaproxy.zap.extension.accessControl.widgets.SiteNodeIcons.LEAF_ICON;
import static org.zaproxy.zap.extension.accessControl.widgets.SiteNodeIcons.LEAF_ICON_CHECK;
import static org.zaproxy.zap.extension.accessControl.widgets.SiteNodeIcons.LEAF_ICON_CROSS;
import static org.zaproxy.zap.extension.accessControl.widgets.SiteNodeIcons.ROOT_ICON;

import java.awt.Color;
import java.awt.Component;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jdesktop.swingx.JXTreeTable;
import org.jdesktop.swingx.treetable.DefaultTreeTableModel;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.zaproxy.zap.extension.accessControl.AccessRule;
import org.zaproxy.zap.extension.accessControl.ContextAccessRulesManager;
import org.zaproxy.zap.extension.accessControl.ExtensionAccessControl;
import org.zaproxy.zap.extension.accessControl.widgets.SiteTreeNode;
import org.zaproxy.zap.extension.users.ExtensionUserManagement;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.users.User;
import org.zaproxy.zap.view.AbstractContextPropertiesPanel;
import org.zaproxy.zap.view.LayoutHelper;
import org.zaproxy.zap.view.widgets.ContextPanelUsersSelectComboBox;

/** The context configuration panel used for specifying the Access Control rules. */
@SuppressWarnings("serial")
public class ContextAccessControlPanel extends AbstractContextPropertiesPanel {

    private static final Logger log = LogManager.getLogger(ContextAccessControlPanel.class);
    private static final long serialVersionUID = -7569788230643264454L;

    private static final String PANEL_NAME =
            Constant.messages.getString("accessControl.contextPanel.title");
    private static final String UNAUTHENTICATED_USER_NAME =
            Constant.messages.getString("accessControl.contextPanel.user.unauthenticated");

    private ExtensionAccessControl extension;
    private static ExtensionUserManagement usersExtension;

    private JXTreeTable tree;
    private JScrollPane treePane;
    private ContextPanelUsersSelectComboBox usersComboBox;

    private int selectedUserId = 0;
    private Map<Integer, ContextUserAccessRulesModel> userModels;
    private ContextAccessRulesManager internalRulesManager;

    public ContextAccessControlPanel(ExtensionAccessControl extensionAccessControl, int contextId) {
        super(contextId);
        this.extension = extensionAccessControl;
        this.userModels = new HashMap<>();
        this.selectedUserId = 0;
        initializeView();
    }

    /** Initialize the panel. */
    private void initializeView() {
        this.setName(getContextId() + ": " + PANEL_NAME);
        this.setLayout(new GridBagLayout());

        this.add(
                new JLabel(
                        Constant.messages.getHtmlWrappedString(
                                "accessControl.contextPanel.label.description")),
                LayoutHelper.getGBC(0, 0, 2, 1.0D, new Insets(0, 0, 10, 0)));

        // The user selection box
        this.add(
                new JLabel(Constant.messages.getString("accessControl.contextPanel.label.user")),
                LayoutHelper.getGBC(0, 1, 1, 0.0D));
        this.add(getUsersComboBox(), LayoutHelper.getGBC(1, 1, 1, 1.0D, new Insets(0, 5, 0, 5)));

        // The site tree for the access rules of each context
        this.add(
                getContextSiteTreePane(),
                LayoutHelper.getGBC(
                        0, 2, 2, 1.0D, 1.0D, GridBagConstraints.BOTH, new Insets(10, 0, 0, 5)));

        // The warning regarding changing structure parameters
        this.add(
                new JLabel(
                        Constant.messages.getHtmlWrappedString(
                                "accessControl.contextPanel.label.warning")),
                LayoutHelper.getGBC(0, 3, 2, 1.0D));
    }

    private JScrollPane getContextSiteTreePane() {
        if (treePane == null) {
            // Initialize the tree and pane to display it
            tree = new JXTreeTable();
            treePane = new JScrollPane(tree);
            treePane.setBorder(
                    BorderFactory.createEtchedBorder(javax.swing.border.EtchedBorder.RAISED));

            // Set up the tree accordingly
            tree.setShowsRootHandles(true);
            tree.setRootVisible(true);
            tree.setTreeCellRenderer(new AccessRuleNodeCellRenderer());

            // Set up the editor for the Access Rules so it displays as a combo-box
            JComboBox<AccessRule> comboBox =
                    new JComboBox<>(
                            new AccessRule[] {
                                AccessRule.ALLOWED, AccessRule.DENIED, AccessRule.INHERIT
                            });
            tree.setDefaultEditor(AccessRule.class, new DefaultCellEditor(comboBox));
        }
        return treePane;
    }

    private ContextUserAccessRulesModel getUserAccessRulesModel(int userId) {
        log.debug("Getting user model for: {}", userId);
        ContextUserAccessRulesModel model = userModels.get(userId);
        if (model == null) {
            model = new ContextUserAccessRulesModel(userId, internalRulesManager);
            userModels.put(userId, model);
        }
        return model;
    }

    private ContextPanelUsersSelectComboBox getUsersComboBox() {
        if (usersComboBox == null) {
            usersComboBox = new ContextPanelUsersSelectComboBox(getContextId());

            // We need to add a 'custom' user for allowing setting access rules for unauthenticated
            // visitors. The custom user will have the id '-1' which is an id that should not be
            // generated for normal users.
            User unauthenticatedUser =
                    new User(getContextId(), UNAUTHENTICATED_USER_NAME, UNAUTHENTICATED_USER_ID);
            unauthenticatedUser.setEnabled(true);
            usersComboBox.setCustomUsers(new User[] {unauthenticatedUser});

            usersComboBox.addActionListener(
                    e -> {
                        User selectedUser = usersComboBox.getSelectedUser();
                        if (selectedUser != null) {
                            selectedUserId = selectedUser.getId();
                            tree.setVisible(true);
                            if (internalRulesManager != null) {
                                tree.setTreeTableModel(getUserAccessRulesModel(selectedUserId));
                            }
                            tree.expandAll();
                        } else {
                            tree.setVisible(false);
                            tree.setTreeTableModel(new DefaultTreeTableModel());
                            tree.expandAll();
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
        log.debug("Initing panel for context: {}", uiSharedContext.getId());

        // Clone the Access Rules Manager so we can support canceling any changes. If the internal
        // manager already existed, just copy the rules, otherwise create a cloned one.

        // NOTE: We are setting the internal context in the ContextAccessRulesManager as the 'real'
        // Context instead of the UI one, as the ContextSiteTree is, currently, reloaded only in
        // here and with the field separators that have been already defined. If any changes are
        // done to the the field separators in the currently open SessionProperties Dialog, they
        // will not be visible in the tree. Thus, in order to keep consistency, we stick to also
        // using the 'real' Context in the internal Rules Manager so any rules are inferred
        // according to the 'old' field separators.
        // TODO: Eventually we should find a better solution for the above issue
        ContextAccessRulesManager originalManager =
                extension.getContextAccessRulesManager(uiSharedContext.getId());
        if (internalRulesManager == null) {
            Context context = Model.getSingleton().getSession().getContext(getContextId());
            this.internalRulesManager = new ContextAccessRulesManager(context, originalManager);
        } else {
            internalRulesManager.copyRulesFrom(
                    originalManager,
                    getUsersManagementExtension().getUIConfiguredUsers(getContextId()));
        }

        // Re-generate the context tree so we are up-to-date
        this.internalRulesManager.getContextSiteTree().reloadTree(session, uiSharedContext);

        // Clear the cache of the previous models so the models get recreated just for the users
        // that need it
        this.userModels.clear();

        // Re-set the tree table model for the selected user, forcing a reloading
        if (getUsersComboBox().getSelectedUser() != null) {
            tree.setTreeTableModel(
                    getUserAccessRulesModel(usersComboBox.getSelectedUser().getId()));
            tree.expandAll();
        }
    }

    @Override
    public void validateContextData(Session session) {
        // Nothing to validate
    }

    @Override
    public void saveTemporaryContextData(Context uiSharedContext) {
        // Nothing to save as the data is already saved in the 'tempRulesManager'
    }

    @Override
    public void saveContextData(Session session) {
        List<User> users = getUsersManagementExtension().getUIConfiguredUsers(getContextId());
        extension
                .getContextAccessRulesManager(getContextId())
                .copyRulesFrom(internalRulesManager, users);
    }

    @Override
    public String getHelpIndex() {
        return "accessControl.contextOptions";
    }

    /** Unloads the panel, to detach it from core (persistent) classes. */
    public void unload() {
        getUsersComboBox().unload();
    }

    private static ExtensionUserManagement getUsersManagementExtension() {
        if (usersExtension == null) {
            usersExtension =
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionUserManagement.class);
            if (usersExtension == null) {
                throw new IllegalStateException(
                        "The required Users Management extension could not be loaded.");
            }
        }
        return usersExtension;
    }

    private static final Color COLOR_DENIED = Color.RED;
    private static final Color COLOR_ALLOWED = new Color(31, 131, 31);
    private static final Color COLOR_DENIED_FOCUS = new Color(255, 195, 195);
    private static final Color COLOR_ALLOWED_FOCUS = new Color(195, 255, 195);

    /**
     * A custom cell renderer used for the tree of access rules that sets custom colors and icons
     * depending on the node and the inferred rule.
     */
    private class AccessRuleNodeCellRenderer extends DefaultTreeCellRenderer {

        private static final long serialVersionUID = 5863120297397993899L;

        @Override
        public Component getTreeCellRendererComponent(
                JTree tree,
                Object value,
                boolean selected,
                boolean expanded,
                boolean isLeaf,
                int row,
                boolean hasFocus) {

            super.getTreeCellRendererComponent(
                    tree, value, selected, expanded, isLeaf, row, hasFocus);

            if (!(value instanceof SiteTreeNode)) return this;

            // Depending on the state of the node and the infer rule, set the icon and color
            // accordingly
            SiteTreeNode node = (SiteTreeNode) value;
            if (node != null) {
                if (node.isRoot() || node.getUri() == null) {
                    setIcon(ROOT_ICON); // 'World' icon
                } else {
                    // Infer the rule so we can draw accordinglyF
                    AccessRule rule = internalRulesManager.inferRule(selectedUserId, node);
                    switch (rule) {
                        case ALLOWED:
                            // Text color
                            if (selected) {
                                this.setForeground(COLOR_ALLOWED_FOCUS);
                            } else {
                                this.setForeground(COLOR_ALLOWED);
                            }

                            // Icon
                            if (isLeaf) {
                                setIcon(LEAF_ICON_CHECK);
                            } else if (expanded) {
                                setIcon(FOLDER_OPEN_ICON_CHECK);
                            } else {
                                setIcon(FOLDER_CLOSED_ICON_CHECK);
                            }
                            break;
                        case DENIED:
                            // Text color
                            if (selected) {
                                this.setForeground(COLOR_DENIED_FOCUS);
                            } else {
                                this.setForeground(COLOR_DENIED);
                            }

                            // Icon
                            if (isLeaf) {
                                setIcon(LEAF_ICON_CROSS);
                            } else if (expanded) {
                                setIcon(FOLDER_OPEN_ICON_CROSS);
                            } else {
                                setIcon(FOLDER_CLOSED_ICON_CROSS);
                            }
                            break;
                        default:
                            // Icon
                            if (isLeaf) {
                                setIcon(LEAF_ICON);
                            } else if (expanded) {
                                setIcon(FOLDER_OPEN_ICON);
                            } else {
                                setIcon(FOLDER_CLOSED_ICON);
                            }
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
