/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
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
package org.zaproxy.zap.extension.accessControl;

import java.awt.Dimension;
import java.awt.Frame;

import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.accessControl.AccessControlScannerThread.AccessControlScanStartOptions;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.scan.ScanStartOptions;
import org.zaproxy.zap.users.User;
import org.zaproxy.zap.view.StandardFieldsDialog;
import org.zaproxy.zap.view.widgets.ContextSelectComboBox;
import org.zaproxy.zap.view.widgets.UsersMultiSelectTable;

/**
 * The dialog shown to allow users to configure {@link ScanStartOptions} for the Access Control
 * testing.
 */
public class AccessControlScanOptionsDialog extends StandardFieldsDialog {

	private static final long serialVersionUID = -4540976404891062951L;

	private static final String FIELD_CONTEXT = "accessControl.scanOptions.label.context";
	private static final String FIELD_USERS = "accessControl.scanOptions.label.users";
	private static final String UNAUTHENTICATED_USER_NAME = Constant.messages
			.getString("accessControl.scanOptions.unauthenticatedUser");

	private ExtensionAccessControl extension;
	private UsersMultiSelectTable usersSelectTable;

	public AccessControlScanOptionsDialog(ExtensionAccessControl extension, Frame owner, Dimension dim) {
		super(owner, "accessControl.scanOptions.title", dim);
		this.extension = extension;
	}

	public void init(Context context) {
		this.removeAllFields();

		usersSelectTable = new UsersMultiSelectTable(context.getIndex());
		// We add a 'custom' user that corresponds to sending unauthenticated user so that ZAP users
		// can select this option as well
		usersSelectTable.addCustomUser(new User(context.getIndex(), UNAUTHENTICATED_USER_NAME));

		this.addContextSelectField(FIELD_CONTEXT, context);
		this.addTableField(FIELD_USERS, usersSelectTable);
		this.addPadding();
	}

	@Override
	public String getSaveButtonText() {
		return Constant.messages.getString("accessControl.scanOptions.button.scan");
	}

	@Override
	public void save() {
		// In this case, the 'Save' action corresponds to starting a scan with the specified options
		AccessControlScanStartOptions startOptions = new AccessControlScanStartOptions();
		startOptions.targetContext = ((ContextSelectComboBox) getField(FIELD_CONTEXT)).getSelectedContext();
		startOptions.targetUsers = usersSelectTable.getSelectedUsers();
		extension.startScan(startOptions);
	}

	@Override
	public String validateFields() {
		Context selectedContext = ((ContextSelectComboBox) getField(FIELD_CONTEXT)).getSelectedContext();
		if (selectedContext == null) {
			return Constant.messages.getString("accessControl.scanOptions.error.noContext");
		}
		if (usersSelectTable.getSelectedUsersCount() < 2) {
			return Constant.messages.getString("accessControl.scanOptions.error.noUsers");
		}
		return null;
	}
}
