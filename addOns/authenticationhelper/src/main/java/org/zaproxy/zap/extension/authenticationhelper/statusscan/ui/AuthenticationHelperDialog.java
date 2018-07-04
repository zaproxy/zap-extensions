/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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
package org.zaproxy.zap.extension.authenticationhelper.statusscan.ui;

import java.awt.Dimension;
import java.awt.Frame;
import java.awt.GridBagConstraints;
import java.awt.Insets;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JButton;
import javax.swing.JPanel;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.zaproxy.zap.extension.authenticationhelper.ExtensionAuthenticationHelper;
import org.zaproxy.zap.extension.authenticationhelper.statusscan.ui.AuthenticationConfigurationChecklistPanel.ConfigurationStatus;
import org.zaproxy.zap.extension.users.ExtensionUserManagement;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.model.Target;
import org.zaproxy.zap.users.User;
import org.zaproxy.zap.view.LayoutHelper;
import org.zaproxy.zap.view.StandardFieldsDialog;

public class AuthenticationHelperDialog extends StandardFieldsDialog {

    private static final long serialVersionUID = 8166856842235224527L;

    private static final Logger logger = Logger.getLogger(AuthenticationHelperDialog.class);

    private static final String FIELD_START = "authenticationhelper.dialog.label.start";
    private static final String FIELD_CONTEXT = "authenticationhelper.dialog.label.context";
    private static final String FIELD_USER = "authenticationhelper.dialog.label.user";

    private JButton[] extraButtons;

    private AuthenticationConfigurationChecklistPanel checklistPanel;

    private ExtensionAuthenticationHelper extensionAuthenticationHelper = null;
    private ExtensionUserManagement extensionUserManagement = null;

    private Target target = null;

    public AuthenticationHelperDialog(
            ExtensionAuthenticationHelper ext, Frame owner, Dimension dim) {
        super(
                owner,
                "authenticationhelper.dialog.title",
                dim,
                new String[] {"authenticationhelper.dialog.title"});
        this.extensionAuthenticationHelper = ext;
    }

    public void init(Target scanTarget) {
        if (scanTarget != null) {
            target = scanTarget;
        }
        if (logger.isDebugEnabled()) {
            if (target == null) {
                logger.debug("initializing authentication status check dialog without target");
            } else {
                logger.debug(
                        "initializing check authentication status dialog for target: "
                                + target.getStartNode().getName());
            }
        }

        removeAllFields();

        addTargetSelectField(0, FIELD_START, target, true, false);
        addComboField(0, FIELD_CONTEXT, new String[] {}, "");
        addComboField(0, FIELD_USER, new String[] {}, "");
        addCustomPanel(0, getChecklistPanel());
        addUsersToUserComboField();
        getChecklistPanel().runCheck();

        addFieldListener(
                FIELD_CONTEXT,
                e -> {
                    addUsersToUserComboField();
                    getChecklistPanel().runCheck();
                });

        addFieldListener(
                FIELD_USER,
                e -> {
                    getChecklistPanel().runCheck();
                });

        targetSelected(FIELD_START, target);
        addUsersToUserComboField();

        setTabScrollable("authenticationhelper.tab.authenticationStatus", true);

        pack();
    }

    @Override
    public String getHelpIndex() {
        return "authenticationhelper.dialog";
    }

    // TODO: get rid of reflection
    @SuppressWarnings("unchecked")
    private void addCustomPanel(int tabIndex, JPanel customPanel) {
        Method incTabOffset;
        try {
            incTabOffset = getClass().getSuperclass().getDeclaredMethod("incTabOffset", int.class);
            incTabOffset.setAccessible(true);

            Field fieldTabPanels = getClass().getSuperclass().getDeclaredField("tabPanels");
            fieldTabPanels.setAccessible(true);
            Field fieldTabOffSets = getClass().getSuperclass().getDeclaredField("tabOffsets");
            fieldTabOffSets.setAccessible(true);

            List<JPanel> tabPanels = (List<JPanel>) fieldTabPanels.get(this);
            List<Integer> tabOffsets = (List<Integer>) fieldTabOffSets.get(this);

            tabPanels
                    .get(tabIndex)
                    .add(
                            customPanel,
                            LayoutHelper.getGBC(
                                    0,
                                    tabOffsets.get(tabIndex),
                                    2,
                                    1.0D,
                                    1.0D,
                                    GridBagConstraints.BOTH,
                                    new Insets(4, 4, 4, 4)));

            incTabOffset.invoke(this, tabIndex);
        } catch (Exception e) {
            logger.debug(e.getMessage(), e);
        }
    }

    private AuthenticationConfigurationChecklistPanel getChecklistPanel() {
        if (checklistPanel == null) {
            checklistPanel = new AuthenticationConfigurationChecklistPanel(this);
        }
        return checklistPanel;
    }

    @Override
    public void targetSelected(String field, Target node) {
        List<String> ctxNames = new ArrayList<String>();
        if (node != null) {
            // The user has selected a new node
            target = node;
        }
        if (target != null) {
            if (target.getStartNode() != null) {
                Session session = Model.getSingleton().getSession();
                List<Context> contexts = session.getContextsForNode(target.getStartNode());
                for (Context context : contexts) {
                    ctxNames.add(context.getName());
                }
            } else if (target.getContext() != null) {
                ctxNames.add(target.getContext().getName());
            }
        }
        setComboFields(FIELD_CONTEXT, ctxNames, "");
        getField(FIELD_CONTEXT).setEnabled(ctxNames.size() > 0);
        getChecklistPanel().runCheck();
    }

    public Context getSelectedContext() {
        String ctxName = getStringValue(FIELD_CONTEXT);
        if (getExtensionUserManagement() != null && !isEmptyField(FIELD_CONTEXT)) {
            Session session = Model.getSingleton().getSession();
            return session.getContext(ctxName);
        }
        return null;
    }

    public User getSelectedUser() {
        Context context = getSelectedContext();
        if (context != null) {
            String userName = getStringValue(FIELD_USER);
            if (userName == null) {
                return null;
            }
            List<User> users =
                    this.getExtensionUserManagement()
                            .getContextUserAuthManager(context.getIndex())
                            .getUsers();
            for (User user : users) {
                if (userName.equals(user.getName())) {
                    return user;
                }
            }
        }
        return null;
    }

    private void addUsersToUserComboField() {
        Context context = getSelectedContext();
        List<String> userNames = new ArrayList<String>();
        if (context != null) {
            List<User> users =
                    this.getExtensionUserManagement()
                            .getContextUserAuthManager(context.getIndex())
                            .getUsers();
            for (User user : users) {
                userNames.add(user.getName());
            }
        }
        setComboFields(FIELD_USER, userNames, "");
        getField(FIELD_USER).setEnabled(userNames.size() > 0);
    }

    private ExtensionUserManagement getExtensionUserManagement() {
        if (extensionUserManagement == null) {
            extensionUserManagement =
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionUserManagement.class);
        }
        return extensionUserManagement;
    }

    public Target getTarget() {
        return target;
    }

    @Override
    public void save() {
        List<Object> contextSpecificObjects = new ArrayList<Object>();
        target.setContext(this.getSelectedContext());
        contextSpecificObjects.add(extensionAuthenticationHelper.getOptionsParam());
        contextSpecificObjects.add(getSelectedContext().getAuthenticationMethod());

        extensionAuthenticationHelper.startScan(
                target, getSelectedUser(), contextSpecificObjects.toArray());
    }

    @Override
    public String validateFields() {
        if (getChecklistPanel().getConfigurationStatus().equals(ConfigurationStatus.BAD)) {
            return Constant.messages.getString("authenticationhelper.dialog.error");
        } else if (getChecklistPanel()
                .getConfigurationStatus()
                .equals(ConfigurationStatus.NOT_VALIDATED_YET)) {
            return Constant.messages.getString("authenticationhelper.dialog.error.refresh");
        }
        return null;
    }

    @Override
    public JButton[] getExtraButtons() {
        if (extraButtons == null) {
            JButton refreshButton = new JButton("Refresh");

            refreshButton.addActionListener(
                    e -> {
                        setPreviouslySelectedUser();
                        checklistPanel.runCheck();
                    });

            extraButtons = new JButton[] {refreshButton};
        }
        return extraButtons;
    }

    private void setPreviouslySelectedUser() {
        String previouslySelectedUser = getStringValue(FIELD_USER);
        targetSelected(FIELD_START, target);
        if (previouslySelectedUser != null) {
            setFieldValue(FIELD_USER, previouslySelectedUser);
        }
    }

    @Override
    public String getSaveButtonText() {
        return Constant.messages.getString("authenticationhelper.dialog.btn.scan");
    }

    public void reset() {
        target = null;
        init(target);
        repaint();
    }
}
