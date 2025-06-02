/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2015 The ZAP Development Team
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

import javax.swing.JCheckBox;
import javax.swing.JOptionPane;
import javax.swing.SortOrder;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.view.AbstractMultipleOptionsTablePanel;

public class AjaxSpiderMultipleOptionsPanel
        extends AbstractMultipleOptionsTablePanel<AjaxSpiderParamElem> {

    private static final long serialVersionUID = -115340627058929308L;

    private static final String REMOVE_DIALOG_TITLE =
            Constant.messages.getString("spiderajax.options.dialog.elem.remove.title");
    private static final String REMOVE_DIALOG_TEXT =
            Constant.messages.getString("spiderajax.options.dialog.elem.remove.text");

    private static final String REMOVE_DIALOG_CONFIRM_BUTTON_LABEL =
            Constant.messages.getString("spiderajax.options.dialog.elem.remove.button.confirm");
    private static final String REMOVE_DIALOG_CANCEL_BUTTON_LABEL =
            Constant.messages.getString("spiderajax.options.dialog.elem.remove.button.cancel");

    private static final String REMOVE_DIALOG_CHECKBOX_LABEL =
            Constant.messages.getString("spiderajax.options.dialog.elem.remove.checkbox.label");

    private DialogAddElem addDialog = null;
    private DialogModifyElem modifyDialog = null;

    private OptionsAjaxSpiderTableModel model;

    public AjaxSpiderMultipleOptionsPanel(OptionsAjaxSpiderTableModel model) {
        super(model);

        this.model = model;

        getTable().getColumnExt(0).setPreferredWidth(5);
        getTable().setSortOrder(1, SortOrder.ASCENDING);
        getTable().setVisibleRowCount(5);
    }

    @Override
    public AjaxSpiderParamElem showAddDialogue() {
        if (addDialog == null) {
            addDialog = new DialogAddElem(View.getSingleton().getOptionsDialog(null));
            addDialog.pack();
        }
        addDialog.setElems(model.getElements());
        addDialog.setVisible(true);

        AjaxSpiderParamElem elem = addDialog.getElem();
        addDialog.clear();

        return elem;
    }

    @Override
    public AjaxSpiderParamElem showModifyDialogue(AjaxSpiderParamElem e) {
        if (modifyDialog == null) {
            modifyDialog = new DialogModifyElem(View.getSingleton().getOptionsDialog(null));
            modifyDialog.pack();
        }
        modifyDialog.setElems(model.getElements());
        modifyDialog.setElem(e);
        modifyDialog.setVisible(true);

        AjaxSpiderParamElem elem = modifyDialog.getElem();
        modifyDialog.clear();

        if (!elem.equals(e)) {
            return elem;
        }

        return null;
    }

    @Override
    public boolean showRemoveDialogue(AjaxSpiderParamElem e) {
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
