/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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
package org.zaproxy.addon.automation.gui;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.Window;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.SortOrder;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.automation.ContextWrapper.StructureData;
import org.zaproxy.zap.view.AbstractMultipleOptionsBaseTableModel;
import org.zaproxy.zap.view.AbstractMultipleOptionsBaseTablePanel;
import org.zaproxy.zap.view.StandardFieldsDialog;

@SuppressWarnings("serial")
public class ContextStructurePanel extends JPanel {

    private static final long serialVersionUID = 1L;

    private ParametersTableModel parametersTableModel;

    public ContextStructurePanel(Window parent) {
        this.setLayout(new BorderLayout());

        parametersTableModel = new ParametersTableModel();

        add(
                new JLabel(
                        Constant.messages.getString(
                                "automation.dialog.structure.structuralparameters")),
                BorderLayout.NORTH);
        add(
                new DataDrivenNodesMultipleOptionsPanel(parent, parametersTableModel),
                BorderLayout.CENTER);
    }

    public StructureData getStructure() {
        var structure = new StructureData();
        structure.setStructuralParameters(parametersTableModel.getElements());
        return structure;
    }

    public void setStructure(StructureData structure) {
        parametersTableModel.setElements(structure.getStructuralParameters());
    }

    private static class DataDrivenNodesMultipleOptionsPanel
            extends AbstractMultipleOptionsBaseTablePanel<String> {

        private static final long serialVersionUID = 1L;

        private static final String REMOVE_DIALOG_TITLE =
                Constant.messages.getString(
                        "automation.dialog.structure.structuralparameters.remove.title");
        private static final String REMOVE_DIALOG_TEXT =
                Constant.messages.getString(
                        "automation.dialog.structure.structuralparameters.remove.text");

        private static final String REMOVE_DIALOG_CONFIRM_BUTTON_LABEL =
                Constant.messages.getString("all.button.remove");
        private static final String REMOVE_DIALOG_CANCEL_BUTTON_LABEL =
                Constant.messages.getString("all.button.cancel");

        private static final String REMOVE_DIALOG_CHECKBOX_LABEL =
                Constant.messages.getString("all.prompt.dontshow");

        private Window parent;

        public DataDrivenNodesMultipleOptionsPanel(Window parent, ParametersTableModel model) {
            super(model);

            this.parent = parent;

            getTable().setSortOrder(0, SortOrder.ASCENDING);
            getTable().packAll();
        }

        @Override
        public String showAddDialogue() {
            StructuralParameterDialog ddnDialog =
                    new StructuralParameterDialog(
                            parent,
                            "automation.dialog.structure.structuralparameters.dialog.add.title",
                            new Dimension(500, 200));

            return ddnDialog.showDialog(null);
        }

        @Override
        public String showModifyDialogue(String ddn) {
            StructuralParameterDialog ddnDialog =
                    new StructuralParameterDialog(
                            parent,
                            "automation.dialog.structure.structuralparameters.dialog.modify.title",
                            new Dimension(500, 200));

            return ddnDialog.showDialog(ddn);
        }

        @Override
        public boolean showRemoveDialogue(String e) {
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

    private static class ParametersTableModel
            extends AbstractMultipleOptionsBaseTableModel<String> {

        private static final long serialVersionUID = 1L;

        private static final String[] COLUMN_NAMES = {
            Constant.messages.getString(
                    "automation.dialog.structure.structuralparameters.table.header.name")
        };

        private final List<String> parameters;

        public ParametersTableModel() {
            parameters = new ArrayList<>();
        }

        @Override
        public int getColumnCount() {
            return COLUMN_NAMES.length;
        }

        @Override
        public String getColumnName(int column) {
            return COLUMN_NAMES[column];
        }

        @Override
        public Class<?> getColumnClass(int columnIndex) {
            return String.class;
        }

        @Override
        public boolean isCellEditable(int rowIndex, int columnIndex) {
            return false;
        }

        @Override
        public int getRowCount() {
            return parameters.size();
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            if (columnIndex == 0) {
                return parameters.get(rowIndex);
            }
            return null;
        }

        @Override
        public List<String> getElements() {
            return parameters;
        }

        public void setElements(List<String> parameters) {
            this.parameters.clear();
            this.parameters.addAll(parameters);
            this.fireTableDataChanged();
        }
    }

    private static class StructuralParameterDialog extends StandardFieldsDialog {

        private static final long serialVersionUID = 1L;

        private static final String FIELD_NAME =
                "automation.dialog.structure.structuralparameters.dialog.label.name";

        private String parameter;

        public StructuralParameterDialog(Window owner, String titleLabel, Dimension dim) {
            super(owner, titleLabel, dim, true);
        }

        public String showDialog(String name) {
            addTextField(FIELD_NAME, name != null ? name : "");
            setVisible(true);

            return parameter;
        }

        @Override
        public void save() {
            parameter = getStringValue(FIELD_NAME);
        }

        @Override
        public String validateFields() {
            var name = getStringValue(FIELD_NAME);
            if (name == null || name.isBlank()) {
                return Constant.messages.getString(
                        "automation.dialog.structure.structuralparameters.dialog.error.name");
            }
            return null;
        }
    }
}
