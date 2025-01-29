/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
import java.util.List;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.SortOrder;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.utils.EnableableInterface;
import org.zaproxy.zap.view.AbstractMultipleOptionsBaseTableModel;
import org.zaproxy.zap.view.AbstractMultipleOptionsBaseTablePanel;
import org.zaproxy.zap.view.AbstractMultipleOrderedOptionsBaseTableModel;
import org.zaproxy.zap.view.AbstractMultipleOrderedOptionsBaseTablePanel;

public class StepsPanel {

    private final Dialog parent;
    private final boolean enableable;

    private JPanel panel;

    private final AuthenticationStepsTableModel stepsModel;

    private DialogAddStep addDialog;
    private DialogModifyStep modifyDialog;

    /**
     * Constructs a {@code StepsPanel} with the given properties.
     *
     * @param parent the parent dialog, to form a proper dialog hierarchy.
     * @param enableable {@code true} if the steps can be enabled/disabled, {@code false} otherwise.
     */
    public StepsPanel(Dialog parent, boolean enableable) {
        this.parent = parent;
        this.enableable = enableable;

        panel = new JPanel(new BorderLayout());
        JLabel label =
                new JLabel(
                        Constant.messages.getString(
                                "authhelper.auth.method.browser.steps.ui.panel.label"));
        panel.add(label, BorderLayout.PAGE_START);

        stepsModel = new AuthenticationStepsTableModel(enableable);
        JComponent stepsPanel =
                enableable ? new OptionsPanel(stepsModel) : new NonEnabledOptionsPanel(stepsModel);
        label.setLabelFor(stepsPanel);
        panel.add(stepsPanel);
    }

    public JPanel getPanel() {
        return panel;
    }

    public void setSteps(List<AuthenticationStep> steps) {
        stepsModel.setSteps(steps);
    }

    public List<AuthenticationStep> getSteps() {
        return stepsModel.getElements();
    }

    private <T> AuthenticationStep showAddDialogue(
            AbstractMultipleOptionsBaseTableModel<AuthenticationStep> model) {
        if (addDialog == null) {
            addDialog = new DialogAddStep(parent);
            addDialog.setEnableable(enableable);
            addDialog.pack();
        }
        addDialog.setSteps(model.getElements());
        addDialog.setVisible(true);

        AuthenticationStep elem = addDialog.getStep();
        addDialog.clear();
        return elem;
    }

    private <T> AuthenticationStep showModifyDialogue(
            AbstractMultipleOptionsBaseTableModel<AuthenticationStep> model, AuthenticationStep e) {
        if (modifyDialog == null) {
            modifyDialog = new DialogModifyStep(parent);
            modifyDialog.setEnableable(enableable);
            modifyDialog.pack();
        }
        modifyDialog.setSteps(model.getElements());
        modifyDialog.setStep(e);
        modifyDialog.setVisible(true);

        AuthenticationStep elem = modifyDialog.getStep();
        modifyDialog.clear();

        if (!elem.equals(e)) {
            return elem;
        }

        return null;
    }

    private <T extends EnableableInterface> boolean showRemoveDialogue(
            AbstractMultipleOptionsBaseTablePanel<T> optionsPanel) {
        JCheckBox removeWithoutConfirmationCheckBox =
                new JCheckBox(
                        Constant.messages.getString(
                                "authhelper.auth.method.browser.steps.ui.remove.checkbox.label"));
        Object[] messages = {
            Constant.messages.getString("authhelper.auth.method.browser.steps.ui.remove.text"),
            " ",
            removeWithoutConfirmationCheckBox
        };
        int option =
                JOptionPane.showOptionDialog(
                        parent,
                        messages,
                        Constant.messages.getString(
                                "authhelper.auth.method.browser.steps.ui.remove.title"),
                        JOptionPane.OK_CANCEL_OPTION,
                        JOptionPane.QUESTION_MESSAGE,
                        null,
                        new String[] {
                            Constant.messages.getString(
                                    "authhelper.auth.method.browser.steps.ui.remove.button.confirm"),
                            Constant.messages.getString(
                                    "authhelper.auth.method.browser.steps.ui.remove.button.cancel")
                        },
                        null);

        if (option == JOptionPane.OK_OPTION) {
            optionsPanel.setRemoveWithoutConfirmation(
                    removeWithoutConfirmationCheckBox.isSelected());

            return true;
        }

        return false;
    }

    private class NonEnabledOptionsPanel
            extends AbstractMultipleOrderedOptionsBaseTablePanel<AuthenticationStep> {

        private static final long serialVersionUID = 1L;

        public NonEnabledOptionsPanel(AuthenticationStepsTableModel model) {
            super(model);

            addMoveButtons();

            getTable().setSortOrder(0, SortOrder.ASCENDING);
            getTable().setVisibleRowCount(5);
        }

        @Override
        public AuthenticationStep showAddDialogue() {
            return StepsPanel.this.showAddDialogue(getMultipleOptionsModel());
        }

        @Override
        public AuthenticationStep showModifyDialogue(AuthenticationStep e) {
            return StepsPanel.this.showModifyDialogue(getMultipleOptionsModel(), e);
        }

        @Override
        public boolean showRemoveDialogue(AuthenticationStep e) {
            return StepsPanel.this.showRemoveDialogue(this);
        }
    }

    private class OptionsPanel
            extends AbstractMultipleOrderedOptionsBaseTablePanel<AuthenticationStep> {

        private static final long serialVersionUID = 1L;

        public OptionsPanel(AuthenticationStepsTableModel model) {
            super(model);

            addMoveButtons();

            getTable().getColumnExt(0).setPreferredWidth(5);
            getTable().getColumnExt(1).setPreferredWidth(10);
            getTable().setSortOrder(1, SortOrder.ASCENDING);
            getTable().setVisibleRowCount(5);
        }

        @Override
        public AuthenticationStep showAddDialogue() {
            return StepsPanel.this.showAddDialogue(getMultipleOptionsModel());
        }

        @Override
        public AuthenticationStep showModifyDialogue(AuthenticationStep e) {
            return StepsPanel.this.showModifyDialogue(getMultipleOptionsModel(), e);
        }

        @Override
        public boolean showRemoveDialogue(AuthenticationStep e) {
            return StepsPanel.this.showRemoveDialogue(this);
        }
    }

    @SuppressWarnings("serial")
    private static class AuthenticationStepsTableModel
            extends AbstractMultipleOrderedOptionsBaseTableModel<AuthenticationStep> {

        private static final long serialVersionUID = 1L;

        private static final List<String> COLUMN_NAMES =
                List.of(
                        Constant.messages.getString(
                                "authhelper.auth.method.browser.steps.ui.table.header.enabled"),
                        "#",
                        Constant.messages.getString(
                                "authhelper.auth.method.browser.steps.ui.table.header.description"));

        private final boolean enabledColumn;
        private List<AuthenticationStep> steps;

        public AuthenticationStepsTableModel(boolean enabledColumn) {
            this.enabledColumn = enabledColumn;

            steps = new ArrayList<>(0);
        }

        @Override
        public List<AuthenticationStep> getElements() {
            return steps;
        }

        public void setSteps(List<AuthenticationStep> steps) {
            this.steps = new ArrayList<>(steps.size());

            for (AuthenticationStep step : steps) {
                this.steps.add(new AuthenticationStep(step));
            }

            fireTableDataChanged();
        }

        @Override
        public String getColumnName(int col) {
            return COLUMN_NAMES.get(getEffectiveColumnIndex(col));
        }

        @Override
        public int getColumnCount() {
            return COLUMN_NAMES.size() - (enabledColumn ? 0 : 1);
        }

        @Override
        public Class<?> getColumnClass(int c) {
            switch (getEffectiveColumnIndex(c)) {
                case 0:
                    return Boolean.class;
                case 1:
                    return Integer.class;

                default:
                    return String.class;
            }
        }

        @Override
        public int getRowCount() {
            return steps.size();
        }

        @Override
        public boolean isCellEditable(int rowIndex, int columnIndex) {
            return getEffectiveColumnIndex(columnIndex) == 0;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            switch (getEffectiveColumnIndex(columnIndex)) {
                case 0:
                    return Boolean.valueOf(getElement(rowIndex).isEnabled());
                case 1:
                    return getElement(rowIndex).getOrder();
                case 2:
                    return getElement(rowIndex).getDescription();
                default:
                    return null;
            }
        }

        private int getEffectiveColumnIndex(int columnIndex) {
            return enabledColumn ? columnIndex : columnIndex + 1;
        }

        @Override
        public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
            if (getEffectiveColumnIndex(columnIndex) == 0 && aValue instanceof Boolean) {
                steps.get(rowIndex).setEnabled(((Boolean) aValue).booleanValue());
                fireTableCellUpdated(rowIndex, columnIndex);
            }
        }
    }
}
