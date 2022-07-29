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
package org.zaproxy.zap.extension.scripts;

import java.awt.Component;
import java.text.MessageFormat;
import javax.swing.JOptionPane;
import javax.swing.JTree;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionPopupMenuItem;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.view.SessionDialog;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.authentication.AuthenticationMethodType;
import org.zaproxy.zap.authentication.ScriptBasedAuthenticationMethodType;
import org.zaproxy.zap.authentication.ScriptBasedAuthenticationMethodType.ScriptBasedAuthenticationMethod;
import org.zaproxy.zap.extension.authentication.ContextAuthenticationPanel;
import org.zaproxy.zap.extension.authentication.ExtensionAuthentication;
import org.zaproxy.zap.extension.script.ScriptNode;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.users.ExtensionUserManagement;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.view.popup.ExtensionPopupMenuComponent;

/**
 * The Popup that allows users to set, for a Context, the authentication method to Script-Based
 * Authentication and directly load the Authentication script.
 */
@SuppressWarnings("serial")
public class PopupUseScriptAsAuthenticationScript extends ExtensionPopupMenuItem {

    private static final Logger log =
            LogManager.getLogger(PopupUseScriptAsAuthenticationScript.class);
    private static final long serialVersionUID = -9073920896139520588L;

    /** The Constant menu name. */
    private static final String MENU_NAME =
            Constant.messages.getString("scripts.popup.scriptBasedAuth");

    private static final String PARENT_MENU_NAME =
            Constant.messages.getString("scripts.popup.useForContextAs");

    /** The scripts UI extension. */
    private ExtensionScriptsUI extension = null;

    /** The users extension. */
    private static ExtensionUserManagement usersExtension;

    /** The context id. */
    private int contextId;

    /**
     * Checks whether the prerequisites for enabling this Popup are satisfied.
     *
     * @return true, if they are satisfied
     */
    public static boolean arePrerequisitesSatisfied() {
        // Make sure the AuthenticationMethod extension is registered
        ExtensionAuthentication authExtension =
                (ExtensionAuthentication)
                        Control.getSingleton()
                                .getExtensionLoader()
                                .getExtension(ExtensionAuthentication.NAME);
        if (authExtension == null) {
            log.info(
                    "Use Script For Authentication Popup disabled: The Authentication extension is not enabled.");
            return false;
        }

        // Make sure the ScriptBasedAuthenticationMethodType is registered
        AuthenticationMethodType scriptType =
                authExtension.getAuthenticationMethodTypeForIdentifier(
                        ScriptBasedAuthenticationMethodType.METHOD_IDENTIFIER);
        if (scriptType == null) {
            log.info(
                    "Use Script For Authentication Popup disabled: The ScriptBasedAuthentication method type is not registered.");
            return false;
        }

        return true;
    }

    /**
     * Instantiates a new popup.
     *
     * @param extension the scripts UI extension
     * @param ctx the context
     */
    public PopupUseScriptAsAuthenticationScript(ExtensionScriptsUI extension, Context ctx) {
        super();
        this.extension = extension;
        this.contextId = ctx.getId();

        this.setText(MessageFormat.format(MENU_NAME, ctx.getName()));
        this.addActionListener(
                e -> {
                    ScriptWrapper script =
                            PopupUseScriptAsAuthenticationScript.this
                                    .extension
                                    .getScriptsPanel()
                                    .getSelectedScript();
                    if (script != null) {
                        performAction(script);
                    }
                });
    }

    /**
     * Gets the Users extension.
     *
     * @return the users extension
     */
    private ExtensionUserManagement getUsersExtension() {
        if (usersExtension == null) {
            usersExtension =
                    (ExtensionUserManagement)
                            Control.getSingleton()
                                    .getExtensionLoader()
                                    .getExtension(ExtensionUserManagement.NAME);
        }
        return usersExtension;
    }

    /**
     * Make sure the user acknowledges the Users corresponding to this context will be deleted.
     *
     * @param uiSharedContext the ui shared context
     * @return true, if successful
     */
    private boolean confirmUsersDeletion(Context uiSharedContext) {
        if (getUsersExtension() != null) {
            if (getUsersExtension().getSharedContextUsers(uiSharedContext).size() > 0) {
                int choice =
                        JOptionPane.showConfirmDialog(
                                this,
                                Constant.messages.getString(
                                        "authentication.dialog.confirmChange.label"),
                                Constant.messages.getString(
                                        "authentication.dialog.confirmChange.title"),
                                JOptionPane.OK_CANCEL_OPTION);
                if (choice == JOptionPane.CANCEL_OPTION) {
                    return false;
                }
            }
        }
        return true;
    }

    /**
     * Perform the actual action.
     *
     * @param script the script
     */
    private void performAction(ScriptWrapper script) {
        // Manually create the UI shared contexts so any modifications are done
        // on an UI shared Context, so changes can be undone by pressing Cancel
        SessionDialog sessionDialog = View.getSingleton().getSessionDialog();
        sessionDialog.recreateUISharedContexts(Model.getSingleton().getSession());
        final Context uiSharedContext = sessionDialog.getUISharedContext(this.contextId);

        // Do the work/changes on the UI shared context
        if (uiSharedContext.getAuthenticationMethod() instanceof ScriptBasedAuthenticationMethod) {
            log.info(
                    "Selected Authentication script via popup menu. Changing existing Script-Based Authentication instance for Context {}",
                    contextId);
            ScriptBasedAuthenticationMethod method =
                    (ScriptBasedAuthenticationMethod) uiSharedContext.getAuthenticationMethod();
            try {
                method.loadScript(script);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(
                        this,
                        ex.getMessage(),
                        Constant.messages.getString(
                                "authentication.method.script.dialog.error.title"),
                        JOptionPane.ERROR_MESSAGE);
                return;
            }

            // Show the session dialog without recreating UI Shared contexts
            View.getSingleton()
                    .showSessionDialog(
                            Model.getSingleton().getSession(),
                            ContextAuthenticationPanel.buildName(this.contextId),
                            false);
        } else {
            log.info(
                    "Selected Authentication script via popup menu. Creating new Script-Based Authentication instance for Context {}",
                    this.contextId);
            ScriptBasedAuthenticationMethod method =
                    new ScriptBasedAuthenticationMethodType().createAuthenticationMethod(contextId);

            try {
                method.loadScript(script);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(
                        this,
                        ex.getMessage(),
                        Constant.messages.getString(
                                "authentication.method.script.dialog.error.title"),
                        JOptionPane.ERROR_MESSAGE);
                return;
            }
            if (!confirmUsersDeletion(uiSharedContext)) {
                log.debug("Cancelled change of authentication type.");
                return;
            }

            uiSharedContext.setAuthenticationMethod(method);

            // Show the session dialog without recreating UI Shared contexts
            // NOTE: First init the panels of the dialog so old users data gets loaded and just then
            // delete the users from the UI data model, otherwise the 'real' users from the
            // non-shared context would be loaded and would override any deletions made.
            View.getSingleton()
                    .showSessionDialog(
                            Model.getSingleton().getSession(),
                            ContextAuthenticationPanel.buildName(this.contextId),
                            false,
                            () -> {
                                // Removing the users from the 'shared context' (the UI)
                                // will cause their removal at
                                // save as well
                                if (getUsersExtension() != null)
                                    getUsersExtension().removeSharedContextUsers(uiSharedContext);
                            });
        }
    }

    @Override
    public boolean isEnableForComponent(Component invoker) {
        boolean enable = isEnable(invoker);
        if (!enable) {
            View.getSingleton().getPopupList().remove(this);
        }
        return enable;
    }

    private boolean isEnable(Component invoker) {
        // Enable the popup just for the scripts tree
        if (invoker.getName() != null && invoker.getName().equals(ScriptsListPanel.TREE)) {
            try {

                JTree tree = (JTree) invoker;
                ScriptNode node = (ScriptNode) tree.getLastSelectedPathComponent();

                // And only for a script node
                if (node == null
                        || node.isTemplate()
                        || node.getUserObject() == null
                        || !(node.getUserObject() instanceof ScriptWrapper)) {
                    return false;
                }

                // And only if the script's type is Authentication
                ScriptWrapper script = extension.getScriptsPanel().getSelectedScript();
                return script != null
                        && script.getEngine() != null
                        && script.getTypeName()
                                .equals(ScriptBasedAuthenticationMethodType.SCRIPT_TYPE_AUTH);
            } catch (Exception e) {
                log.debug(e);
            }
        }
        return false;
    }

    @Override
    public boolean isSubMenu() {
        return true;
    }

    @Override
    public String getParentMenuName() {
        return PARENT_MENU_NAME;
    }

    @Override
    public void dismissed(ExtensionPopupMenuComponent selectedMenuComponent) {
        View.getSingleton().getPopupList().remove(this);
    }
}
