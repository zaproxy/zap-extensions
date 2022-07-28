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

import java.awt.Dimension;
import java.awt.Frame;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import org.apache.commons.lang.ArrayUtils;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.control.Control.Mode;
import org.parosproxy.paros.core.scanner.Alert;
import org.zaproxy.zap.extension.accessControl.AccessControlScannerThread.AccessControlScanStartOptions;
import org.zaproxy.zap.extension.accessControl.ExtensionAccessControl;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.scan.ScanStartOptions;
import org.zaproxy.zap.users.User;
import org.zaproxy.zap.view.StandardFieldsDialog;
import org.zaproxy.zap.view.widgets.ContextSelectComboBox;
import org.zaproxy.zap.view.widgets.UsersMultiSelectTable;

/**
 * The dialog shown to allow users to configure {@link ScanStartOptions} for the Access Control
 * testing.
 *
 * <p>If the un-authenticated user was selected, it is returned in the {@link ScanStartOptions} as
 * <code>null</code>.
 */
@SuppressWarnings("serial")
public class AccessControlScanOptionsDialog extends StandardFieldsDialog {

    private static final long serialVersionUID = -4540976404891062951L;

    private static final String FIELD_CONTEXT = "accessControl.scanOptions.label.context";
    private static final String FIELD_USERS = "accessControl.scanOptions.label.users";
    private static final String FIELD_RAISE_ALERTS = "accessControl.scanOptions.label.raiseAlerts";
    private static final String FIELD_ALERTS_RISK = "accessControl.scanOptions.label.alertsRisk";
    private static final String UNAUTHENTICATED_USER_NAME =
            Constant.messages.getString("accessControl.scanOptions.unauthenticatedUser");

    private ExtensionAccessControl extension;
    private UsersMultiSelectTable usersSelectTable;

    /** This is the "custom" user that will allow scanning also as an "unauthenticated" user. */
    private User unauthenticatedUser;

    public AccessControlScanOptionsDialog(
            ExtensionAccessControl extension, Frame owner, Dimension dim) {
        super(owner, "accessControl.scanOptions.title", dim);
        this.extension = extension;
    }

    public void init(Context context) {
        this.removeAllFields();

        usersSelectTable = new UsersMultiSelectTable(context.getId());
        unauthenticatedUser = new User(context.getId(), UNAUTHENTICATED_USER_NAME);
        usersSelectTable.addCustomUser(unauthenticatedUser);

        this.addContextSelectField(FIELD_CONTEXT, context);
        this.addTableField(FIELD_USERS, usersSelectTable);
        this.addCheckBoxField(FIELD_RAISE_ALERTS, true);
        this.addComboField(FIELD_ALERTS_RISK, Alert.MSG_RISK, Alert.MSG_RISK[Alert.RISK_HIGH]);
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
        startOptions.setTargetContext(
                ((ContextSelectComboBox) getField(FIELD_CONTEXT)).getSelectedContext());
        startOptions.setTargetUsers(usersSelectTable.getSelectedUsers());
        // If the un-authenticated user was selected, replace it with a 'null' user
        if (startOptions.getTargetUsers().remove(unauthenticatedUser)) {
            startOptions.getTargetUsers().add(null);
        }
        startOptions.setRaiseAlerts(((JCheckBox) getField(FIELD_RAISE_ALERTS)).isSelected());
        // Just to make sure we have a reference here to MSG_RISK for taking care when refactoring
        // and that this still works if somehow the connection between index and value is lost, we
        // perform a quick search
        @SuppressWarnings("unchecked")
        String selectedAlertRisk =
                (String) ((JComboBox<String>) getField(FIELD_ALERTS_RISK)).getSelectedItem();
        startOptions.setAlertRiskLevel(ArrayUtils.indexOf(Alert.MSG_RISK, selectedAlertRisk));
        extension.startScan(startOptions);
    }

    @Override
    public String validateFields() {
        Context selectedContext =
                ((ContextSelectComboBox) getField(FIELD_CONTEXT)).getSelectedContext();
        if (selectedContext == null) {
            return Constant.messages.getString("accessControl.scanOptions.error.noContext");
        }
        if (usersSelectTable.getSelectedUsersCount() < 1) {
            return Constant.messages.getString("accessControl.scanOptions.error.noUsers");
        }

        Mode mode = Control.getSingleton().getMode();
        if (Mode.safe.equals(mode)) {
            return Constant.messages.getString("accessControl.scanOptions.error.mode.safe");
        } else if (Mode.protect.equals(mode)) {
            if (!selectedContext.isInScope()) {
                return Constant.messages.getString(
                        "accessControl.scanOptions.error.mode.protected",
                        selectedContext.getName());
            }
        }

        return null;
    }
}
