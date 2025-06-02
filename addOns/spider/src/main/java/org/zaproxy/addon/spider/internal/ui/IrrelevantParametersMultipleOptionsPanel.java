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
package org.zaproxy.addon.spider.internal.ui;

import java.util.List;
import javax.swing.JCheckBox;
import javax.swing.JOptionPane;
import javax.swing.SortOrder;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.spider.internal.IrrelevantParameter;
import org.zaproxy.zap.view.AbstractMultipleOptionsTablePanel;

public class IrrelevantParametersMultipleOptionsPanel
        extends AbstractMultipleOptionsTablePanel<IrrelevantParameter> {

    private static final long serialVersionUID = 2332044353650231701L;

    private static final String REMOVE_DIALOG_TITLE =
            Constant.messages.getString("spider.options.irrelevantparameter.dialog.remove.title");
    private static final String REMOVE_DIALOG_TEXT =
            Constant.messages.getString("spider.options.irrelevantparameter.dialog.remove.text");

    private static final String REMOVE_DIALOG_CONFIRM_BUTTON_LABEL =
            Constant.messages.getString(
                    "spider.options.irrelevantparameter.dialog.remove.button.confirm");
    private static final String REMOVE_DIALOG_CANCEL_BUTTON_LABEL =
            Constant.messages.getString(
                    "spider.options.irrelevantparameter.dialog.remove.button.cancel");

    private static final String REMOVE_DIALOG_CHECKBOX_LABEL =
            Constant.messages.getString(
                    "spider.options.irrelevantparameter.dialog.remove.checkbox.label");

    private DialogAddIrrelevantParameter addDialog;
    private DialogModifyIrrelevantParameter modifyDialog;

    public IrrelevantParametersMultipleOptionsPanel() {
        super(new IrrelevantParametersTableModel());

        getTable().setVisibleRowCount(5);
        getTable().setSortOrder(2, SortOrder.ASCENDING);
    }

    public void setIrrelevantParameters(List<IrrelevantParameter> irrelevantParameters) {
        getMultipleOptionsModel().setElements(irrelevantParameters);
    }

    public List<IrrelevantParameter> getIrrelevantParameters() {
        return getMultipleOptionsModel().getElements();
    }

    @Override
    protected IrrelevantParametersTableModel getMultipleOptionsModel() {
        return (IrrelevantParametersTableModel) super.getMultipleOptionsModel();
    }

    @Override
    public IrrelevantParameter showAddDialogue() {
        if (addDialog == null) {
            addDialog =
                    new DialogAddIrrelevantParameter(View.getSingleton().getOptionsDialog(null));
            addDialog.pack();
        }
        addDialog.setVisible(true);

        IrrelevantParameter hostAuthentication = addDialog.getIrrelevantParameter();
        addDialog.clear();

        return hostAuthentication;
    }

    @Override
    public IrrelevantParameter showModifyDialogue(IrrelevantParameter e) {
        if (modifyDialog == null) {
            modifyDialog =
                    new DialogModifyIrrelevantParameter(View.getSingleton().getOptionsDialog(null));
            modifyDialog.pack();
        }
        modifyDialog.setIrrelevantParameter(e);
        modifyDialog.setVisible(true);

        IrrelevantParameter excludedDomain = modifyDialog.getIrrelevantParameter();
        modifyDialog.clear();

        if (!excludedDomain.equals(e)) {
            return excludedDomain;
        }

        return null;
    }

    @Override
    public boolean showRemoveDialogue(IrrelevantParameter e) {
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
