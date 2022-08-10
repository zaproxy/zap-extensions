/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2017 The ZAP Development Team
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
package org.zaproxy.zap.extension.replacer;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Window;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.SortOrder;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.view.AbstractParamPanel;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.view.AbstractMultipleOptionsTablePanel;

@SuppressWarnings("serial")
public class OptionsReplacerPanel extends AbstractParamPanel {

    public static final String PANEL_NAME = Constant.messages.getString("replacer.options.title");
    private static final long serialVersionUID = 1L;

    private ReplacerMultipleOptionsPanel replacerOptionsPanel;

    private OptionsReplacerTableModel replacerModel;

    public OptionsReplacerPanel() {
        super();

        this.setName(PANEL_NAME);
        this.setLayout(new GridBagLayout());

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.weightx = 1.0;
        gbc.anchor = GridBagConstraints.LINE_START;
        gbc.fill = GridBagConstraints.BOTH;

        this.add(new JLabel(Constant.messages.getString("replacer.options.label.tokens")), gbc);

        replacerOptionsPanel = new ReplacerMultipleOptionsPanel(getReplacerTableModel());

        gbc.weighty = 1.0;
        this.add(replacerOptionsPanel, gbc);
    }

    @Override
    public void initParam(Object obj) {
        OptionsParam optionsParam = (OptionsParam) obj;
        ReplacerParam param = optionsParam.getParamSet(ReplacerParam.class);
        getReplacerTableModel().setRules(param.getRules());
        replacerOptionsPanel.setRemoveWithoutConfirmation(!param.isConfirmRemoveToken());
        replacerOptionsPanel.setReplacerParam(param);
    }

    @Override
    public void validateParam(Object obj) throws Exception {}

    @Override
    public void saveParam(Object obj) throws Exception {
        OptionsParam optionsParam = (OptionsParam) obj;
        ReplacerParam replacerParam = optionsParam.getParamSet(ReplacerParam.class);
        replacerParam.setRules(getReplacerTableModel().getElements());
        replacerParam.setConfirmRemoveToken(!replacerOptionsPanel.isRemoveWithoutConfirmation());
    }

    private OptionsReplacerTableModel getReplacerTableModel() {
        if (replacerModel == null) {
            replacerModel = new OptionsReplacerTableModel();
        }
        return replacerModel;
    }

    @Override
    public String getHelpIndex() {
        return "replacer";
    }

    private static class ReplacerMultipleOptionsPanel
            extends AbstractMultipleOptionsTablePanel<ReplacerParamRule> {

        private static final long serialVersionUID = -115340627058929308L;

        private static final String REMOVE_DIALOG_TITLE =
                Constant.messages.getString("replacer.options.dialog.token.remove.title");
        private static final String REMOVE_DIALOG_TEXT =
                Constant.messages.getString("replacer.options.dialog.token.remove.text");

        private static final String REMOVE_DIALOG_CONFIRM_BUTTON_LABEL =
                Constant.messages.getString("replacer.options.dialog.token.remove.button.confirm");
        private static final String REMOVE_DIALOG_CANCEL_BUTTON_LABEL =
                Constant.messages.getString("replacer.options.dialog.token.remove.button.cancel");

        private static final String REMOVE_DIALOG_CHECKBOX_LABEL =
                Constant.messages.getString("replacer.options.dialog.token.remove.checkbox.label");

        private ReplacerParam replacerParam;
        private ReplaceRuleAddDialog addDialog;
        private ReplaceRuleModifyDialog modifyDialog;

        public ReplacerMultipleOptionsPanel(OptionsReplacerTableModel model) {
            super(model);

            this.model = model;

            getTable().getColumnExt(0).setPreferredWidth(25); // checkbox column should be tiny
            getTable().getColumnExt(1).setPreferredWidth(200); // wide Desc Col
            getTable().getColumnExt(2).setPreferredWidth(100); // less wide matchString Column
            getTable().getColumnExt(3).setPreferredWidth(100); // less wide replacement Column
            getTable()
                    .setHorizontalScrollEnabled(
                            true); // descriptions could be very wide, so turn on horiz scroll

            getTable().setAutoCreateRowSorter(true);
            getTable().setSortOrder(1, SortOrder.ASCENDING); // sort by description by default
        }

        @Override
        public ReplacerParamRule showAddDialogue() {
            if (addDialog == null) {
                addDialog =
                        new ReplaceRuleAddDialog(
                                (Window) View.getSingleton().getOptionsDialog(null),
                                "replacer.add.title",
                                replacerParam,
                                (OptionsReplacerTableModel) model);
                addDialog.pack();
            }
            addDialog.setVisible(true);
            ReplacerParamRule rule = addDialog.getRule();
            addDialog.clear();
            return rule;
        }

        @Override
        public ReplacerParamRule showModifyDialogue(ReplacerParamRule r) {
            if (modifyDialog == null) {
                modifyDialog =
                        new ReplaceRuleModifyDialog(
                                (Window) View.getSingleton().getOptionsDialog(null),
                                "replacer.modify.title",
                                replacerParam,
                                (OptionsReplacerTableModel) model);
                modifyDialog.pack();
            }
            modifyDialog.setRule(r);
            modifyDialog.setVisible(true);
            ReplacerParamRule rule = modifyDialog.getRule();
            modifyDialog.clear();
            return rule;
        }

        @Override
        public boolean showRemoveDialogue(ReplacerParamRule e) {
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

        public void setReplacerParam(ReplacerParam replacerParam) {
            this.replacerParam = replacerParam;
        }
    }
}
