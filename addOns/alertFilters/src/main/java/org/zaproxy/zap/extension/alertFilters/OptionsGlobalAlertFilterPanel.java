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

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import javax.swing.JCheckBox;
import javax.swing.JOptionPane;
import javax.swing.SortOrder;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.view.AbstractParamPanel;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.view.AbstractMultipleOptionsTablePanel;

public class OptionsGlobalAlertFilterPanel extends AbstractParamPanel {

    private static final long serialVersionUID = 1L;

    private GlobalAlertFilterMultipleOptionsPanel alertFilterOptionsPanel;

    private AlertFilterTableModel alertFilterModel = null;

    public OptionsGlobalAlertFilterPanel() {
        super();
        initialize();
    }

    private void initialize() {
        this.setName(Constant.messages.getString("alertFilters.global.options.title"));
        this.setLayout(new GridBagLayout());

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.weightx = 1.0;
        gbc.anchor = GridBagConstraints.LINE_START;
        gbc.fill = GridBagConstraints.BOTH;

        alertFilterOptionsPanel = new GlobalAlertFilterMultipleOptionsPanel(getAlertFilterModel());

        gbc.weighty = 1.0;
        this.add(alertFilterOptionsPanel, gbc);
    }

    @Override
    public void initParam(Object obj) {
        OptionsParam optionsParam = (OptionsParam) obj;
        GlobalAlertFilterParam param = optionsParam.getParamSet(GlobalAlertFilterParam.class);
        getAlertFilterModel().setAlertFilters(param.getGlobalAlertFilters());
        alertFilterOptionsPanel.setRemoveWithoutConfirmation(!param.isConfirmRemoveFilter());
    }

    @Override
    public void saveParam(Object obj) throws Exception {
        OptionsParam optionsParam = (OptionsParam) obj;
        GlobalAlertFilterParam param = optionsParam.getParamSet(GlobalAlertFilterParam.class);
        param.setGlobalAlertFilters(getAlertFilterModel().getElements());
        param.setConfirmRemoveFilter(!alertFilterOptionsPanel.isRemoveWithoutConfirmation());
    }

    private AlertFilterTableModel getAlertFilterModel() {
        if (alertFilterModel == null) {
            alertFilterModel = new AlertFilterTableModel();
        }
        return alertFilterModel;
    }

    @Override
    public String getHelpIndex() {
        return "addon.globalAlertFilter";
    }

    private static class GlobalAlertFilterMultipleOptionsPanel
            extends AbstractMultipleOptionsTablePanel<AlertFilter> {

        private static final long serialVersionUID = -115340627058929308L;

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

        private DialogAddAlertFilter addDialog = null;
        private DialogModifyAlertFilter modifyDialog = null;

        public GlobalAlertFilterMultipleOptionsPanel(AlertFilterTableModel model) {
            super(model);

            this.model = model;

            getTable().getColumnExt(0).setPreferredWidth(20);
            getTable().setSortOrder(1, SortOrder.ASCENDING);
        }

        @Override
        public AlertFilter showAddDialogue() {
            if (addDialog == null) {
                addDialog = new DialogAddAlertFilter(View.getSingleton().getOptionsDialog(null));
                addDialog.pack();
            }
            addDialog.setVisible(true);

            AlertFilter filter = addDialog.getAlertFilter();
            addDialog.clear();

            return filter;
        }

        @Override
        public AlertFilter showModifyDialogue(AlertFilter e) {
            if (modifyDialog == null) {
                modifyDialog =
                        new DialogModifyAlertFilter(View.getSingleton().getOptionsDialog(null));
                modifyDialog.pack();
            }
            modifyDialog.setAlertFilter(e);
            modifyDialog.setVisible(true);

            AlertFilter filter = modifyDialog.getAlertFilter();
            modifyDialog.clear();

            if (!filter.equals(e)) {
                return filter;
            }

            return null;
        }

        @Override
        public boolean showRemoveDialogue(AlertFilter e) {
            JCheckBox removeWithoutConfirmationCheckBox =
                    new JCheckBox(REMOVE_DIALOG_CHECKBOX_LABEL);
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
                                REMOVE_DIALOG_CONFIRM_BUTTON_LABEL,
                                REMOVE_DIALOG_CANCEL_BUTTON_LABEL
                            },
                            null);

            if (option == JOptionPane.OK_OPTION) {
                setRemoveWithoutConfirmation(removeWithoutConfirmationCheckBox.isSelected());

                return true;
            }

            return false;
        }
    }
}
