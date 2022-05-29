/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.addon.network.internal.ui;

import java.awt.Dialog;
import javax.swing.JCheckBox;
import javax.swing.JOptionPane;
import javax.swing.SortOrder;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.network.internal.client.Pkcs11Driver;
import org.zaproxy.addon.network.internal.client.Pkcs11Drivers;
import org.zaproxy.zap.view.AbstractMultipleOptionsBaseTablePanel;

public class Pkcs11DriverTablePanel extends AbstractMultipleOptionsBaseTablePanel<Pkcs11Driver> {

    private static final long serialVersionUID = 1L;

    private static final String REMOVE_DIALOG_TITLE =
            Constant.messages.getString("network.ui.options.pkcs11driver.remove.title");
    private static final String REMOVE_DIALOG_TEXT =
            Constant.messages.getString("network.ui.options.pkcs11driver.remove.text");

    private static final String REMOVE_DIALOG_CONFIRM_BUTTON_LABEL =
            Constant.messages.getString("network.ui.options.pkcs11driver.remove.button.confirm");
    private static final String REMOVE_DIALOG_CANCEL_BUTTON_LABEL =
            Constant.messages.getString("network.ui.options.pkcs11driver.remove.button.cancel");

    private static final String REMOVE_DIALOG_CHECKBOX_LABEL =
            Constant.messages.getString("network.ui.options.pkcs11driver.remove.checkbox.label");

    private final Dialog owner;
    private AddPkcs11DriverDialog addDialog;
    private ModifyPkcs11DriverDialog modifyDialog;

    public Pkcs11DriverTablePanel(Dialog owner, Pkcs11Drivers drivers) {
        super(new Pkcs11DriverTableModel(drivers));
        this.owner = owner;

        getTable().setSortOrder(0, SortOrder.ASCENDING);
        getTable().packAll();
    }

    @Override
    public Pkcs11Driver showAddDialogue() {
        if (addDialog == null) {
            addDialog = new AddPkcs11DriverDialog(owner);
            addDialog.pack();
        }
        addDialog.setVisible(true);
        return addDialog.getPkcs11Driver();
    }

    @Override
    public Pkcs11Driver showModifyDialogue(Pkcs11Driver e) {
        if (modifyDialog == null) {
            modifyDialog = new ModifyPkcs11DriverDialog(owner);
            modifyDialog.pack();
        }
        modifyDialog.setPkcs11Driver(e);
        modifyDialog.setVisible(true);

        Pkcs11Driver driver = modifyDialog.getPkcs11Driver();

        if (!driver.equals(e)) {
            return driver;
        }

        return null;
    }

    @Override
    public boolean showRemoveDialogue(Pkcs11Driver e) {
        JCheckBox removeWithoutConfirmationCheckBox = new JCheckBox(REMOVE_DIALOG_CHECKBOX_LABEL);
        Object[] messages = {REMOVE_DIALOG_TEXT, " ", removeWithoutConfirmationCheckBox};
        int option =
                JOptionPane.showOptionDialog(
                        owner,
                        messages,
                        REMOVE_DIALOG_TITLE,
                        JOptionPane.OK_CANCEL_OPTION,
                        JOptionPane.QUESTION_MESSAGE,
                        null,
                        new String[] {
                            REMOVE_DIALOG_CONFIRM_BUTTON_LABEL, REMOVE_DIALOG_CANCEL_BUTTON_LABEL
                        },
                        null);

        if (option == JOptionPane.OK_OPTION) {
            setRemoveWithoutConfirmation(removeWithoutConfirmationCheckBox.isSelected());

            return true;
        }

        return false;
    }
}
