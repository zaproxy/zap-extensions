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

import javax.swing.JCheckBox;
import javax.swing.JOptionPane;
import javax.swing.SortOrder;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.network.internal.server.http.LocalServerConfig;
import org.zaproxy.zap.view.AbstractMultipleOptionsTablePanel;

@SuppressWarnings("serial")
public class LocalServersTablePanel extends AbstractMultipleOptionsTablePanel<LocalServerConfig> {

    private static final long serialVersionUID = 1L;

    private static final String REMOVE_DIALOG_TITLE =
            Constant.messages.getString("network.ui.options.localservers.remove.title");
    private static final String REMOVE_DIALOG_TEXT =
            Constant.messages.getString("network.ui.options.localservers.remove.text");

    private static final String REMOVE_DIALOG_CONFIRM_BUTTON_LABEL =
            Constant.messages.getString("network.ui.options.localservers.remove.button.confirm");
    private static final String REMOVE_DIALOG_CANCEL_BUTTON_LABEL =
            Constant.messages.getString("network.ui.options.localservers.remove.button.cancel");

    private static final String REMOVE_DIALOG_CHECKBOX_LABEL =
            Constant.messages.getString("network.ui.options.localservers.remove.checkbox.label");

    private final AddressValidator addressValidator;
    private AddLocalServerDialog addDialog;
    private ModifyLocalServerDialog modifyDialog;

    public LocalServersTablePanel(AddressValidator addressValidator, LocalServersTableModel model) {
        super(model);

        this.addressValidator = addressValidator;

        getTable().setVisibleRowCount(5);
        getTable().setSortOrder(1, SortOrder.ASCENDING);
    }

    @Override
    public LocalServerConfig showAddDialogue() {
        if (addDialog == null) {
            addDialog =
                    new AddLocalServerDialog(
                            addressValidator, View.getSingleton().getOptionsDialog(null));
            addDialog.pack();
        }
        addDialog.setVisible(true);
        return addDialog.getServerConfig();
    }

    @Override
    public LocalServerConfig showModifyDialogue(LocalServerConfig e) {
        if (modifyDialog == null) {
            modifyDialog =
                    new ModifyLocalServerDialog(
                            addressValidator, View.getSingleton().getOptionsDialog(null));
            modifyDialog.pack();
        }
        modifyDialog.setServerConfig(e);
        modifyDialog.setVisible(true);

        LocalServerConfig serverConfig = modifyDialog.getServerConfig();

        if (!serverConfig.equals(e)) {
            return serverConfig;
        }

        return null;
    }

    @Override
    public boolean showRemoveDialogue(LocalServerConfig e) {
        JCheckBox removeWithoutConfirmationCheckBox = new JCheckBox(REMOVE_DIALOG_CHECKBOX_LABEL);
        Object[] messages = {REMOVE_DIALOG_TEXT, " ", removeWithoutConfirmationCheckBox};
        int option =
                JOptionPane.showOptionDialog(
                        View.getSingleton().getMainFrame(),
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
