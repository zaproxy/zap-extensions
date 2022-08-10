/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2019 The ZAP Development Team
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
package org.zaproxy.zap.extension.alertFilters;

import java.awt.Component;
import java.awt.Window;
import javax.swing.JCheckBox;
import javax.swing.JOptionPane;
import javax.swing.SortOrder;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.view.AbstractMultipleOptionsTablePanel;

@SuppressWarnings("serial")
public class AlertFiltersMultipleOptionsPanel
        extends AbstractMultipleOptionsTablePanel<AlertFilter> {

    private static final long serialVersionUID = -7216673905642941770L;

    private static final String REMOVE_DIALOG_TITLE =
            Constant.messages.getString("alertFilters.dialog.remove.title");
    private static final String REMOVE_DIALOG_TEXT =
            Constant.messages.getString("alertFilters.dialog.remove.text");

    private static final String REMOVE_DIALOG_CONFIRM_BUTTON_LABEL =
            Constant.messages.getString("alertFilters.dialog.remove.button.confirm");
    private static final String REMOVE_DIALOG_CANCEL_BUTTON_LABEL =
            Constant.messages.getString("alertFilters.dialog.remove.button.cancel");

    private static final String REMOVE_DIALOG_CHECKBOX_LABEL =
            Constant.messages.getString("alertFilters.dialog.remove.checkbox.label");

    private ExtensionAlertFilters extension;
    private DialogAddAlertFilter addDialog = null;
    private DialogModifyAlertFilter modifyDialog = null;
    private Context uiSharedContext;
    private Window owner;

    public AlertFiltersMultipleOptionsPanel(
            ExtensionAlertFilters extension, Window owner, AlertFilterTableModel model) {
        super(model);
        this.extension = extension;
        this.owner = owner;

        Component rendererComponent;
        if (getTable().getColumnExt(0).getHeaderRenderer()
                == null) { // If there isn't a header renderer then get the default renderer
            rendererComponent =
                    getTable()
                            .getTableHeader()
                            .getDefaultRenderer()
                            .getTableCellRendererComponent(
                                    null,
                                    getTable().getColumnExt(0).getHeaderValue(),
                                    false,
                                    false,
                                    0,
                                    0);
        } else { // If there is a custom renderer then get it
            rendererComponent =
                    getTable()
                            .getColumnExt(0)
                            .getHeaderRenderer()
                            .getTableCellRendererComponent(
                                    null,
                                    getTable().getColumnExt(0).getHeaderValue(),
                                    false,
                                    false,
                                    0,
                                    0);
        }

        getTable().getColumnExt(0).setMaxWidth(rendererComponent.getMaximumSize().width);
        getTable().setSortOrder(1, SortOrder.ASCENDING);
        getTable().packAll();
    }

    @Override
    public AlertFilter showAddDialogue() {
        return this.showAddDialogue(null);
    }

    public AlertFilter showAddDialogue(AlertFilter alertFilter) {

        if (addDialog == null) {
            addDialog = new DialogAddAlertFilter(this.extension, owner);
            addDialog.pack();
        }
        addDialog.clearFields();
        addDialog.setWorkingContext(this.uiSharedContext);
        addDialog.setCanChangeContext(alertFilter != null);
        addDialog.setAlertFilter(alertFilter);
        addDialog.setVisible(true);

        return addDialog.getAlertFilter();
    }

    @Override
    public AlertFilter showModifyDialogue(AlertFilter alertFilter) {
        return this.showModifyDialogue(alertFilter, false);
    }

    public AlertFilter showModifyDialogue(AlertFilter alertFilter, boolean canChangeContext) {
        if (modifyDialog == null) {
            modifyDialog = new DialogModifyAlertFilter(this.extension, owner);
            modifyDialog.pack();
        }
        modifyDialog.clearFields();
        modifyDialog.setWorkingContext(this.uiSharedContext);
        modifyDialog.setAlertFilter(alertFilter);
        modifyDialog.setCanChangeContext(canChangeContext);
        modifyDialog.setVisible(true);

        return modifyDialog.getAlertFilter();
    }

    @Override
    public boolean showRemoveDialogue(AlertFilter e) {
        JCheckBox removeWithoutConfirmationCheckBox = new JCheckBox(REMOVE_DIALOG_CHECKBOX_LABEL);
        Object[] messages = {REMOVE_DIALOG_TEXT, " ", removeWithoutConfirmationCheckBox};
        int option =
                JOptionPane.showOptionDialog(
                        this,
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

    protected void setWorkingContext(Context context) {
        this.uiSharedContext = context;
    }
}
