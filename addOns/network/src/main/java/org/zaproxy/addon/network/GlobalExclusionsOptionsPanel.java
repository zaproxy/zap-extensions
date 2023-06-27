/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.zaproxy.addon.network;

import java.awt.Dialog;
import java.util.ArrayList;
import java.util.List;
import javax.swing.GroupLayout;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.SortOrder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.view.AbstractParamPanel;
import org.zaproxy.addon.network.internal.GlobalExclusion;
import org.zaproxy.zap.utils.ZapTextField;
import org.zaproxy.zap.view.AbstractFormDialog;
import org.zaproxy.zap.view.AbstractMultipleOptionsTableModel;
import org.zaproxy.zap.view.AbstractMultipleOptionsTablePanel;

@SuppressWarnings("serial")
class GlobalExclusionsOptionsPanel extends AbstractParamPanel {

    private static final long serialVersionUID = 1L;

    private final GlobalExclusionsTableModel tableModel;
    private final GlobalExclusionsTablePanel tablePanel;

    public GlobalExclusionsOptionsPanel(Dialog parent) {
        setName(Constant.messages.getString("network.ui.options.globalexclusions.name"));

        tableModel = new GlobalExclusionsTableModel();
        tablePanel = new GlobalExclusionsTablePanel(parent, tableModel);

        GroupLayout mainLayout = new GroupLayout(this);
        setLayout(mainLayout);
        mainLayout.setAutoCreateGaps(true);
        mainLayout.setAutoCreateContainerGaps(true);

        mainLayout.setHorizontalGroup(mainLayout.createParallelGroup().addComponent(tablePanel));
        mainLayout.setVerticalGroup(mainLayout.createSequentialGroup().addComponent(tablePanel));
    }

    @Override
    public void initParam(Object mainOptions) {
        GlobalExclusionsOptions options = getGlobalExclusionsOptions(mainOptions);

        tableModel.setElements(options.getGlobalExclusions());
        tablePanel.setRemoveWithoutConfirmation(!options.isConfirmRemoveGlobalExclusions());

        tablePanel.pack();
    }

    private static GlobalExclusionsOptions getGlobalExclusionsOptions(Object mainOptions) {
        return ((OptionsParam) mainOptions).getParamSet(GlobalExclusionsOptions.class);
    }

    @Override
    public void validateParam(Object mainOptions) throws Exception {
        // Nothing to do.
    }

    @Override
    public void saveParam(Object mainOptions) throws Exception {
        GlobalExclusionsOptions options = getGlobalExclusionsOptions(mainOptions);

        options.setGlobalExclusions(tableModel.getElements());
        options.setConfirmRemoveGlobalExclusions(!tablePanel.isRemoveWithoutConfirmation());
    }

    @Override
    public String getHelpIndex() {
        return "addon.network.options.globalexclusions";
    }

    private static class GlobalExclusionsTablePanel
            extends AbstractMultipleOptionsTablePanel<GlobalExclusion> {

        private static final long serialVersionUID = 1L;

        private final Dialog parent;
        private boolean firstShown;
        private DialogAddGlobalExclusion addDialog;
        private DialogModifyGlobalExclusion modifyDialog;

        public GlobalExclusionsTablePanel(Dialog parent, GlobalExclusionsTableModel model) {
            super(model);

            this.parent = parent;

            getTable().setSortOrder(1, SortOrder.ASCENDING);

            firstShown = true;
        }

        void pack() {
            if (firstShown) {
                getTable().packAll();
                firstShown = false;
            }
        }

        @Override
        public GlobalExclusion showAddDialogue() {
            if (addDialog == null) {
                addDialog = new DialogAddGlobalExclusion(parent);
                addDialog.pack();
            }
            addDialog.setVisible(true);

            GlobalExclusion elem = addDialog.getElem();
            addDialog.clear();
            return elem;
        }

        @Override
        public GlobalExclusion showModifyDialogue(GlobalExclusion e) {
            if (modifyDialog == null) {
                modifyDialog = new DialogModifyGlobalExclusion(parent);
                modifyDialog.pack();
            }
            modifyDialog.setElem(e);
            modifyDialog.setVisible(true);

            GlobalExclusion elem = modifyDialog.getElem();
            modifyDialog.clear();

            if (!elem.equals(e)) {
                return elem;
            }

            return null;
        }

        @Override
        public boolean showRemoveDialogue(GlobalExclusion e) {
            JCheckBox removeWithoutConfirmationCheckBox =
                    new JCheckBox(
                            Constant.messages.getString(
                                    "network.ui.options.globalexclusions.remove.checkbox.label"));
            Object[] messages = {
                Constant.messages.getString("network.ui.options.globalexclusions.remove.text"),
                " ",
                removeWithoutConfirmationCheckBox
            };
            int option =
                    JOptionPane.showOptionDialog(
                            parent,
                            messages,
                            Constant.messages.getString(
                                    "network.ui.options.globalexclusions.remove.title"),
                            JOptionPane.OK_CANCEL_OPTION,
                            JOptionPane.QUESTION_MESSAGE,
                            null,
                            new String[] {
                                Constant.messages.getString(
                                        "network.ui.options.globalexclusions.remove.button.confirm"),
                                Constant.messages.getString(
                                        "network.ui.options.globalexclusions.remove.button.cancel")
                            },
                            null);

            if (option == JOptionPane.OK_OPTION) {
                setRemoveWithoutConfirmation(removeWithoutConfirmationCheckBox.isSelected());

                return true;
            }

            return false;
        }
    }

    @SuppressWarnings("serial")
    private static class GlobalExclusionsTableModel
            extends AbstractMultipleOptionsTableModel<GlobalExclusion> {

        private static final long serialVersionUID = 1L;

        private static final List<String> COLUMN_NAMES =
                List.of(
                        Constant.messages.getString(
                                "network.ui.options.globalexclusions.table.header.enabled"),
                        Constant.messages.getString(
                                "network.ui.options.globalexclusions.table.header.name"));

        private List<GlobalExclusion> elements;

        public GlobalExclusionsTableModel() {
            elements = List.of();
        }

        @Override
        public List<GlobalExclusion> getElements() {
            return elements;
        }

        public void setElements(List<GlobalExclusion> elems) {
            elements = new ArrayList<>(elems.size());

            for (GlobalExclusion elem : elems) {
                elements.add(new GlobalExclusion(elem));
            }

            fireTableDataChanged();
        }

        @Override
        public String getColumnName(int col) {
            return COLUMN_NAMES.get(col);
        }

        @Override
        public int getColumnCount() {
            return COLUMN_NAMES.size();
        }

        @Override
        public Class<?> getColumnClass(int c) {
            if (c == 0) {
                return Boolean.class;
            }
            return String.class;
        }

        @Override
        public int getRowCount() {
            return elements.size();
        }

        @Override
        public boolean isCellEditable(int rowIndex, int columnIndex) {
            return columnIndex == 0;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            switch (columnIndex) {
                case 0:
                    return Boolean.valueOf(getElement(rowIndex).isEnabled());
                case 1:
                    return getElement(rowIndex).getName();
                default:
                    return null;
            }
        }

        @Override
        public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
            if (columnIndex == 0 && aValue instanceof Boolean) {
                elements.get(rowIndex).setEnabled(((Boolean) aValue).booleanValue());
                fireTableCellUpdated(rowIndex, columnIndex);
            }
        }
    }

    @SuppressWarnings("serial")
    private static class DialogAddGlobalExclusion extends AbstractFormDialog {

        private static final long serialVersionUID = 1L;

        private ZapTextField nameTextField;
        private ZapTextField valueTextField;
        private JCheckBox enabledCheckBox;

        protected GlobalExclusion excludedElement;

        public DialogAddGlobalExclusion(Dialog owner) {
            super(
                    owner,
                    Constant.messages.getString("network.ui.options.globalexclusions.add.title"));
        }

        protected DialogAddGlobalExclusion(Dialog owner, String title) {
            super(owner, title);
        }

        @Override
        protected JPanel getFieldsPanel() {
            JPanel fieldsPanel = new JPanel();

            GroupLayout layout = new GroupLayout(fieldsPanel);
            fieldsPanel.setLayout(layout);
            layout.setAutoCreateGaps(true);
            layout.setAutoCreateContainerGaps(true);

            JLabel descriptionLabel = createLabel("name", getNameTextField());
            JLabel valueLabel = createLabel("value", getValueTextField());
            JLabel enabledLabel = createLabel("enabled", getEnabledCheckBox());

            var documentListener = new EnableButtonDocumentListener();
            getNameTextField().getDocument().addDocumentListener(documentListener);
            getValueTextField().getDocument().addDocumentListener(documentListener);

            layout.setHorizontalGroup(
                    layout.createSequentialGroup()
                            .addGroup(
                                    layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                                            .addComponent(descriptionLabel)
                                            .addComponent(valueLabel)
                                            .addComponent(enabledLabel))
                            .addGroup(
                                    layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                            .addComponent(getNameTextField())
                                            .addComponent(getValueTextField())
                                            .addComponent(getEnabledCheckBox())));

            layout.setVerticalGroup(
                    layout.createSequentialGroup()
                            .addGroup(
                                    layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                            .addComponent(descriptionLabel)
                                            .addComponent(getNameTextField()))
                            .addGroup(
                                    layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                            .addComponent(valueLabel)
                                            .addComponent(getValueTextField()))
                            .addGroup(
                                    layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                            .addComponent(enabledLabel)
                                            .addComponent(getEnabledCheckBox())));

            return fieldsPanel;
        }

        private static JLabel createLabel(String key, JComponent field) {
            JLabel label =
                    new JLabel(
                            Constant.messages.getString(
                                    "network.ui.options.globalexclusions.field." + key));
            label.setLabelFor(field);
            return label;
        }

        @Override
        protected String getConfirmButtonLabel() {
            return Constant.messages.getString("network.ui.options.globalexclusions.add.button");
        }

        @Override
        protected void init() {
            getEnabledCheckBox().setSelected(true);
            excludedElement = null;
        }

        @Override
        protected boolean validateFields() {
            String value = getValueTextField().getText();

            try {
                GlobalExclusion.validatePattern(value);
            } catch (IllegalArgumentException e) {
                JOptionPane.showMessageDialog(
                        this,
                        Constant.messages.getString(
                                "network.ui.options.globalexclusions.warn.invalidregex.message",
                                e.getMessage()),
                        Constant.messages.getString(
                                "network.ui.options.globalexclusions.warn.invalidregex.title"),
                        JOptionPane.INFORMATION_MESSAGE);
                getValueTextField().requestFocusInWindow();
                return false;
            }

            return true;
        }

        private GlobalExclusion createGlobalExclusion() {
            GlobalExclusion element = new GlobalExclusion();
            element.setName(getNameTextField().getText());
            element.setValue(getValueTextField().getText());
            element.setEnabled(getEnabledCheckBox().isSelected());
            return element;
        }

        @Override
        protected void performAction() {
            excludedElement = createGlobalExclusion();
        }

        @Override
        protected void clearFields() {
            reset(getNameTextField());
            reset(getValueTextField());

            getEnabledCheckBox().setSelected(true);
        }

        private static void reset(ZapTextField textField) {
            textField.setText("");
            textField.discardAllEdits();
        }

        public GlobalExclusion getElem() {
            return excludedElement;
        }

        protected ZapTextField getNameTextField() {
            if (nameTextField == null) {
                nameTextField = new ZapTextField(25);
            }
            return nameTextField;
        }

        protected ZapTextField getValueTextField() {
            if (valueTextField == null) {
                valueTextField = new ZapTextField(25);
            }
            return valueTextField;
        }

        protected JCheckBox getEnabledCheckBox() {
            if (enabledCheckBox == null) {
                enabledCheckBox = new JCheckBox();
            }
            return enabledCheckBox;
        }

        public void clear() {
            this.excludedElement = null;
        }

        private class EnableButtonDocumentListener implements DocumentListener {

            @Override
            public void removeUpdate(DocumentEvent e) {
                checkAndEnableConfirmButton();
            }

            @Override
            public void insertUpdate(DocumentEvent e) {
                checkAndEnableConfirmButton();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                checkAndEnableConfirmButton();
            }

            private void checkAndEnableConfirmButton() {
                setConfirmButtonEnabled(
                        isNotEmpty(getNameTextField()) && isNotEmpty(getValueTextField()));
            }

            private boolean isNotEmpty(ZapTextField textField) {
                return textField.getDocument().getLength() > 0;
            }
        }
    }

    private static class DialogModifyGlobalExclusion extends DialogAddGlobalExclusion {

        private static final long serialVersionUID = 1L;

        protected DialogModifyGlobalExclusion(Dialog owner) {
            super(
                    owner,
                    Constant.messages.getString(
                            "network.ui.options.globalexclusions.modify.title"));
        }

        @Override
        protected String getConfirmButtonLabel() {
            return Constant.messages.getString("network.ui.options.globalexclusions.modify.button");
        }

        public void setElem(GlobalExclusion excludedElement) {
            this.excludedElement = excludedElement;
        }

        @Override
        protected void init() {
            setText(excludedElement.getName(), getNameTextField());
            setText(excludedElement.getValue(), getValueTextField());

            getEnabledCheckBox().setSelected(excludedElement.isEnabled());
        }

        private static void setText(String text, ZapTextField textField) {
            textField.setText(text);
            textField.discardAllEdits();
        }
    }
}
