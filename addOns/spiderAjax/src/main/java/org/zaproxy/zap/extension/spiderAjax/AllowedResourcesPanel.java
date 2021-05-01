/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
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
package org.zaproxy.zap.extension.spiderAjax;

import java.awt.BorderLayout;
import java.awt.Dialog;
import javax.swing.JCheckBox;
import javax.swing.JOptionPane;
import javax.swing.SortOrder;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.utils.ZapLabel;
import org.zaproxy.zap.view.AbstractMultipleOptionsTablePanel;

class AllowedResourcesPanel extends AbstractMultipleOptionsTablePanel<AllowedResource> {

    private static final long serialVersionUID = 8762085355395403532L;

    private static final String REMOVE_DIALOG_TITLE =
            Constant.messages.getString("spiderajax.options.dialog.allowedResources.remove.title");
    private static final String REMOVE_DIALOG_TEXT =
            Constant.messages.getString("spiderajax.options.dialog.allowedResources.remove.text");

    private static final String REMOVE_DIALOG_CONFIRM_BUTTON_LABEL =
            Constant.messages.getString(
                    "spiderajax.options.dialog.allowedResources.remove.button.confirm");
    private static final String REMOVE_DIALOG_CANCEL_BUTTON_LABEL =
            Constant.messages.getString(
                    "spiderajax.options.dialog.allowedResources.remove.button.cancel");

    private static final String REMOVE_DIALOG_CHECKBOX_LABEL =
            Constant.messages.getString(
                    "spiderajax.options.dialog.allowedResources.remove.checkbox.label");

    private Dialog owner;
    private AllowedResourcesTableModel model;

    private DialogAddAllowedResource addDialog;
    private DialogModifyAllowedResource modifyDialog;

    public AllowedResourcesPanel(Dialog owner, AllowedResourcesTableModel model) {
        super(model);

        this.owner = owner;
        this.model = model;

        add(
                new ZapLabel(
                        Constant.messages.getString(
                                "spiderajax.options.dialog.allowedResources.label")),
                BorderLayout.NORTH);

        getTable().getColumnExt(0).setPreferredWidth(20);
        getTable().setSortOrder(1, SortOrder.ASCENDING);
        getTable().setVisibleRowCount(5);
    }

    @Override
    public AllowedResource showAddDialogue() {
        if (addDialog == null) {
            addDialog = new DialogAddAllowedResource(owner);
            addDialog.pack();
        }
        addDialog.setAllowedResources(model.getElements());
        addDialog.setVisible(true);

        AllowedResource app = addDialog.getAllowedResource();
        addDialog.clear();

        return app;
    }

    @Override
    public AllowedResource showModifyDialogue(AllowedResource e) {
        if (modifyDialog == null) {
            modifyDialog = new DialogModifyAllowedResource(owner);
            modifyDialog.pack();
        }
        modifyDialog.setAllowedResources(model.getElements());
        modifyDialog.setAllowedResource(e);
        modifyDialog.setVisible(true);

        AllowedResource app = modifyDialog.getAllowedResource();
        modifyDialog.clear();

        if (!app.equals(e)) {
            return app;
        }

        return null;
    }

    @Override
    public boolean showRemoveDialogue(AllowedResource e) {
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
