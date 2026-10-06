/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.addon.authhelper.internal;

import java.awt.BorderLayout;
import java.awt.Dialog;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.view.AbstractMultipleOptionsBaseTableModel;
import org.zaproxy.zap.view.AbstractMultipleOptionsBaseTablePanel;

/** A table, with the standard add/modify/remove controls, to edit name/value parameters. */
public class ExtraParamsPanel {

    private final Dialog parent;
    private final JPanel panel;
    private final ExtraParamsTableModel model;

    private DialogAddExtraParam addDialog;
    private DialogModifyExtraParam modifyDialog;

    /**
     * Constructs a {@code ExtraParamsPanel}.
     *
     * @param parent the parent dialog, to form a proper dialog hierarchy.
     */
    public ExtraParamsPanel(Dialog parent) {
        this.parent = parent;

        panel = new JPanel(new BorderLayout());
        JLabel label =
                new JLabel(
                        Constant.messages.getString(
                                "authhelper.auth.method.oauth2.extraparams.ui.panel.label"));
        panel.add(label, BorderLayout.PAGE_START);

        model = new ExtraParamsTableModel();
        OptionsPanel optionsPanel = new OptionsPanel(model);
        label.setLabelFor(optionsPanel);
        panel.add(optionsPanel);
    }

    public JPanel getPanel() {
        return panel;
    }

    public void setParams(Map<String, String> params) {
        model.setParams(params);
    }

    /** Gets the parameters, in the order shown. */
    public Map<String, String> getParams() {
        Map<String, String> params = new LinkedHashMap<>();
        for (ExtraParam param : model.getElements()) {
            params.put(param.getName(), param.getValue());
        }
        return params;
    }

    private ExtraParam showAddDialogue() {
        if (addDialog == null) {
            addDialog = new DialogAddExtraParam(parent);
            addDialog.pack();
        }
        addDialog.setParams(model.getElements());
        addDialog.setVisible(true);

        ExtraParam elem = addDialog.getParam();
        addDialog.clear();
        return elem;
    }

    private ExtraParam showModifyDialogue(ExtraParam e) {
        if (modifyDialog == null) {
            modifyDialog = new DialogModifyExtraParam(parent);
            modifyDialog.pack();
        }
        modifyDialog.setParams(model.getElements());
        modifyDialog.setParam(e);
        modifyDialog.setVisible(true);

        ExtraParam elem = modifyDialog.getParam();
        modifyDialog.clear();

        if (!elem.equals(e)) {
            return elem;
        }
        return null;
    }

    private boolean showRemoveDialogue(OptionsPanel optionsPanel) {
        JCheckBox removeWithoutConfirmationCheckBox =
                new JCheckBox(
                        Constant.messages.getString(
                                "authhelper.auth.method.oauth2.extraparams.ui.remove.checkbox.label"));
        Object[] messages = {
            Constant.messages.getString("authhelper.auth.method.oauth2.extraparams.ui.remove.text"),
            " ",
            removeWithoutConfirmationCheckBox
        };
        int option =
                JOptionPane.showOptionDialog(
                        parent,
                        messages,
                        Constant.messages.getString(
                                "authhelper.auth.method.oauth2.extraparams.ui.remove.title"),
                        JOptionPane.OK_CANCEL_OPTION,
                        JOptionPane.QUESTION_MESSAGE,
                        null,
                        new String[] {
                            Constant.messages.getString(
                                    "authhelper.auth.method.oauth2.extraparams.ui.remove.button.confirm"),
                            Constant.messages.getString(
                                    "authhelper.auth.method.oauth2.extraparams.ui.remove.button.cancel")
                        },
                        null);

        if (option == JOptionPane.OK_OPTION) {
            optionsPanel.setRemoveWithoutConfirmation(
                    removeWithoutConfirmationCheckBox.isSelected());
            return true;
        }
        return false;
    }

    private class OptionsPanel extends AbstractMultipleOptionsBaseTablePanel<ExtraParam> {

        private static final long serialVersionUID = 1L;

        OptionsPanel(ExtraParamsTableModel model) {
            super(model);
            getTable().setVisibleRowCount(4);
        }

        @Override
        public ExtraParam showAddDialogue() {
            return ExtraParamsPanel.this.showAddDialogue();
        }

        @Override
        public ExtraParam showModifyDialogue(ExtraParam e) {
            return ExtraParamsPanel.this.showModifyDialogue(e);
        }

        @Override
        public boolean showRemoveDialogue(ExtraParam e) {
            return ExtraParamsPanel.this.showRemoveDialogue(this);
        }
    }

    @SuppressWarnings("serial")
    static class ExtraParamsTableModel extends AbstractMultipleOptionsBaseTableModel<ExtraParam> {

        private static final long serialVersionUID = 1L;

        private static final String[] COLUMN_NAMES = {
            Constant.messages.getString(
                    "authhelper.auth.method.oauth2.extraparams.ui.table.header.name"),
            Constant.messages.getString(
                    "authhelper.auth.method.oauth2.extraparams.ui.table.header.value")
        };

        private List<ExtraParam> params = new ArrayList<>(0);

        @Override
        public List<ExtraParam> getElements() {
            return params;
        }

        void setParams(Map<String, String> newParams) {
            params = new ArrayList<>();
            if (newParams != null) {
                newParams.forEach((k, v) -> params.add(new ExtraParam(k, v)));
            }
            fireTableDataChanged();
        }

        @Override
        public String getColumnName(int col) {
            return COLUMN_NAMES[col];
        }

        @Override
        public int getColumnCount() {
            return COLUMN_NAMES.length;
        }

        @Override
        public Class<?> getColumnClass(int c) {
            return String.class;
        }

        @Override
        public int getRowCount() {
            return params.size();
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            ExtraParam param = params.get(rowIndex);
            return columnIndex == 0 ? param.getName() : param.getValue();
        }
    }
}
