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
package org.zaproxy.addon.network.internal.ui.ratelimit;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.SortOrder;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.view.AbstractParamPanel;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.network.internal.ratelimit.RateLimitOptions;
import org.zaproxy.addon.network.internal.ratelimit.RateLimitRule;
import org.zaproxy.zap.view.AbstractMultipleOptionsTablePanel;

@SuppressWarnings("serial")
public class RateLimitOptionsPanel extends AbstractParamPanel {
    private static final long serialVersionUID = 1L;

    public static final String PANEL_NAME =
            Constant.messages.getString("network.ui.ratelimit.options.title");

    private final RateLimitMultipleOptionsPanel rateLimitOptionsPanel;

    private OptionsRateLimitTableModel rateLimitModel;

    public RateLimitOptionsPanel() {
        super();

        this.setName(PANEL_NAME);
        this.setLayout(new GridBagLayout());

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.weightx = 1.0;
        gbc.anchor = GridBagConstraints.LINE_START;
        gbc.fill = GridBagConstraints.BOTH;

        this.add(
                new JLabel(Constant.messages.getString("network.ui.ratelimit.options.label.rules")),
                gbc);

        rateLimitOptionsPanel = new RateLimitMultipleOptionsPanel(getRateLimitTableModel());

        gbc.weighty = 1.0;
        this.add(rateLimitOptionsPanel, gbc);
    }

    @Override
    public void initParam(Object obj) {
        OptionsParam optionsParam = (OptionsParam) obj;
        RateLimitOptions param = optionsParam.getParamSet(RateLimitOptions.class);
        getRateLimitTableModel().setRules(param.getRules());
        rateLimitOptionsPanel.setRateLimitParam(param);
    }

    @Override
    public void validateParam(Object obj) throws Exception {}

    @Override
    public void saveParam(Object obj) throws Exception {
        OptionsParam optionsParam = (OptionsParam) obj;
        RateLimitOptions replacerParam = optionsParam.getParamSet(RateLimitOptions.class);
        replacerParam.setRules(getRateLimitTableModel().getElements());
    }

    private OptionsRateLimitTableModel getRateLimitTableModel() {
        if (rateLimitModel == null) {
            rateLimitModel = new OptionsRateLimitTableModel();
        }
        return rateLimitModel;
    }

    @Override
    public String getHelpIndex() {
        return "addon.network.options.ratelimit";
    }

    private static class RateLimitMultipleOptionsPanel
            extends AbstractMultipleOptionsTablePanel<RateLimitRule> {

        private static final long serialVersionUID = -115340627058929308L;

        private static final String REMOVE_DIALOG_TITLE =
                Constant.messages.getString("network.ui.ratelimit.options.dialog.remove.title");
        private static final String REMOVE_DIALOG_TEXT =
                Constant.messages.getString("network.ui.ratelimit.options.dialog.remove.text");

        private static final String REMOVE_DIALOG_CONFIRM_BUTTON_LABEL =
                Constant.messages.getString(
                        "network.ui.ratelimit.options.dialog.remove.button.confirm");
        private static final String REMOVE_DIALOG_CANCEL_BUTTON_LABEL =
                Constant.messages.getString(
                        "network.ui.ratelimit.options.dialog.remove.button.cancel");

        private static final String REMOVE_DIALOG_CHECKBOX_LABEL =
                Constant.messages.getString(
                        "network.ui.ratelimit.options.dialog.remove.checkbox.label");

        private RateLimitOptions rateLimitOptions;
        private RateLimitRuleAddDialog addDialog;
        private RateLimitRuleModifyDialog modifyDialog;

        public RateLimitMultipleOptionsPanel(OptionsRateLimitTableModel model) {
            super(model);

            this.model = model;

            // descriptions could be very wide, so turn on horiz scroll
            getTable().setHorizontalScrollEnabled(true);

            getTable().setAutoCreateRowSorter(true);
            // sort by description by default
            getTable().setSortOrder(1, SortOrder.ASCENDING);
            getTable().packAll();
        }

        @Override
        public RateLimitRule showAddDialogue() {
            if (addDialog == null) {
                addDialog =
                        new RateLimitRuleAddDialog(
                                View.getSingleton().getOptionsDialog(null),
                                "network.ui.ratelimit.add.title",
                                rateLimitOptions,
                                (OptionsRateLimitTableModel) model);
                addDialog.pack();
            }
            addDialog.setVisible(true);
            RateLimitRule rule = addDialog.getRule();
            addDialog.clear();
            return rule;
        }

        @Override
        public RateLimitRule showModifyDialogue(RateLimitRule r) {
            if (modifyDialog == null) {
                modifyDialog =
                        new RateLimitRuleModifyDialog(
                                View.getSingleton().getOptionsDialog(null),
                                "network.ui.ratelimit.modify.title",
                                rateLimitOptions,
                                (OptionsRateLimitTableModel) model);
                modifyDialog.pack();
            }
            modifyDialog.setRule(r);
            modifyDialog.setVisible(true);
            RateLimitRule rule = modifyDialog.getRule();
            modifyDialog.clear();
            return rule;
        }

        @Override
        public boolean showRemoveDialogue(RateLimitRule e) {
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

        public void setRateLimitParam(RateLimitOptions rateLimitOptions) {
            this.rateLimitOptions = rateLimitOptions;
        }
    }
}
