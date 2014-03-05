/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 * 
 * Copyright 2013 The ZAP Development Team
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); 
 * you may not use this file except in compliance with the License. 
 * You may obtain a copy of the License at 
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0 
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

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionPopupMenuItem;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.view.SessionDialog;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.authentication.ScriptBasedAuthenticationMethodType;
import org.zaproxy.zap.authentication.ScriptBasedAuthenticationMethodType.ScriptBasedAuthenticationMethod;
import org.zaproxy.zap.extension.authentication.ContextAuthenticationPanel;
import org.zaproxy.zap.extension.script.ScriptNode;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.users.ExtensionUserManagement;
import org.zaproxy.zap.model.Context;

public class PopupUseScriptAsAuthenticationScript extends ExtensionPopupMenuItem {

	private static final Logger log = Logger.getLogger(PopupUseScriptAsAuthenticationScript.class);
	private static final String MENU_NAME = Constant.messages.getString("scripts.popup.scriptBasedAuth");
	private static final long serialVersionUID = -9073920896139520588L;
	private ExtensionScriptsUI extension = null;
	private int contextId;
	private ExtensionUserManagement usersExtension;
	private Context uiSharedContext;

	/**
     * 
     */
	public PopupUseScriptAsAuthenticationScript(ExtensionScriptsUI extension, Context ctx) {
		super();
		this.extension = extension;
		this.contextId = ctx.getIndex();
		initialize(ctx);
	}

	/**
	 * This method initializes this
	 */
	private void initialize(Context ctx) {
		this.setText(MessageFormat.format(MENU_NAME, ctx.getName()));

		this.addActionListener(new java.awt.event.ActionListener() {

			@Override
			public void actionPerformed(java.awt.event.ActionEvent e) {
				ScriptWrapper script = extension.getScriptsPanel().getSelectedScript();
				if (script != null) {
					performAction(script);
				}
			}
		});
	}

	/**
	 * Make sure the user acknowledges the Users corresponding to this context will be deleted.
	 * 
	 * @return true, if successful
	 */
	private boolean confirmUsersDeletion(Context uiSharedContext) {
		usersExtension = (ExtensionUserManagement) Control.getSingleton().getExtensionLoader()
				.getExtension(ExtensionUserManagement.NAME);
		if (usersExtension != null) {
			if (usersExtension.getSharedContextUsers(uiSharedContext).size() > 0) {
				int choice = JOptionPane.showConfirmDialog(this,
						Constant.messages.getString("authentication.dialog.confirmChange.label"),
						Constant.messages.getString("authentication.dialog.confirmChange.title"),
						JOptionPane.OK_CANCEL_OPTION);
				if (choice == JOptionPane.CANCEL_OPTION) {
					return false;
				}
			}
		}
		return true;
	}

	private void performAction(ScriptWrapper script) {
		// Manually create the UI shared contexts so any modifications are done
		// on an UI shared Context, so changes can be undone by pressing Cancel
		SessionDialog sessionDialog = View.getSingleton().getSessionDialog();
		sessionDialog.recreateUISharedContexts(Model.getSingleton().getSession());
		uiSharedContext = sessionDialog.getUISharedContext(this.contextId);

		// Do the work/changes on the UI shared context
		if (uiSharedContext.getAuthenticationMethod() instanceof ScriptBasedAuthenticationMethod) {
			log.info("Selected Authentication script via popup menu. Changing existing Script-Based Authentication instance for Context "
					+ contextId);
			ScriptBasedAuthenticationMethod method = (ScriptBasedAuthenticationMethod) uiSharedContext
					.getAuthenticationMethod();
			try {
				method.loadScript(script);
			} catch (Exception ex) {
				JOptionPane.showMessageDialog(this, ex.getMessage(),
						Constant.messages.getString("authentication.method.script.dialog.error.title"),
						JOptionPane.ERROR_MESSAGE);
				return;
			}

			// Show the session dialog without recreating UI Shared contexts
			View.getSingleton().showSessionDialog(Model.getSingleton().getSession(),
					ContextAuthenticationPanel.buildName(this.contextId), false);
		} else {
			log.info("Selected Authentication script via popup menu. Creating new Script-Based Authentication instance for Context "
					+ this.contextId);
			ScriptBasedAuthenticationMethod method = new ScriptBasedAuthenticationMethodType()
					.createAuthenticationMethod(contextId);
			try {
				method.loadScript(script);
			} catch (Exception ex) {
				JOptionPane.showMessageDialog(this, ex.getMessage(),
						Constant.messages.getString("authentication.method.script.dialog.error.title"),
						JOptionPane.ERROR_MESSAGE);
				return;
			}
			if (!confirmUsersDeletion(uiSharedContext)) {
				log.debug("Cancelled change of authentication type.");
				return;
			}
			uiSharedContext.setAuthenticationMethod(method);

			// Show the session dialog without recreating UI Shared contexts
			// NOTE: First init the panels of the dialog so old users data gets
			// loaded and just then delete the users
			// from the UI data model, otherwise the 'real' users from the
			// non-shared context would be loaded
			// and would override any deletions made.
			View.getSingleton().showSessionDialog(Model.getSingleton().getSession(),
					ContextAuthenticationPanel.buildName(this.contextId), false, new Runnable() {

						@Override
						public void run() {
							// Removing the users from the 'shared context' (the UI)
							// will cause their removal at
							// save as well
							if (usersExtension != null)
								usersExtension.removeSharedContextUsers(uiSharedContext);
						}
					});
		}
	}

	@Override
	public boolean isEnableForComponent(Component invoker) {
		if (invoker.getName() != null && invoker.getName().equals(ScriptsListPanel.TREE)) {
			try {
				JTree tree = (JTree) invoker;
				ScriptNode node = (ScriptNode) tree.getLastSelectedPathComponent();

				if (node == null || node.isTemplate() || node.getUserObject() == null
						|| !(node.getUserObject() instanceof ScriptWrapper)) {
					return false;
				}

				ScriptWrapper script = extension.getScriptsPanel().getSelectedScript();

				return script != null
						&& script.getTypeName().equals(ScriptBasedAuthenticationMethodType.SCRIPT_TYPE_AUTH);
			} catch (Exception e) {
				e.printStackTrace();
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
		return Constant.messages.getString("scripts.popup.useForContextAs");
	}

	@Override
	public int getParentMenuIndex() {
		return 1000;
	}
}
