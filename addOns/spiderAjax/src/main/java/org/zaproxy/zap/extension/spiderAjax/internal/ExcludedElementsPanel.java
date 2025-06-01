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
package org.zaproxy.zap.extension.spiderAjax.internal;

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
import org.zaproxy.zap.view.AbstractMultipleOptionsBaseTableModel;
import org.zaproxy.zap.view.AbstractMultipleOptionsBaseTablePanel;
import org.zaproxy.zap.view.AbstractMultipleOptionsTableModel;
import org.zaproxy.zap.view.AbstractMultipleOptionsTablePanel;

/** A panel that allows to manage excluded elements. */
public class ExcludedElementsPanel {

    private final Dialog parent;
    private final boolean enableable;

    private JPanel panel;

    private final ExcludedElementsTableModel excludedElementsModel;

    private DialogAddExcludedElement addDialog;
    private DialogModifyExcludedElement modifyDialog;

    /**
     * Constructs a {@code ExcludedElementsPanel} with the given properties.
     *
     * @param parent the parent dialog, to form a proper dialog hierarchy.
     * @param enableable {@code true} if the excluded elements can be enabled/disabled, {@code
     *     false} otherwise.
     */
    public ExcludedElementsPanel(Dialog parent, boolean enableable) {
        this.parent = parent;
        this.enableable = enableable;

        panel = new JPanel(new BorderLayout());
        JLabel label =
                new JLabel(
                        Constant.messages.getString("spiderajax.excludedelements.ui.panel.label"));
        panel.add(label, BorderLayout.PAGE_START);

        excludedElementsModel = new ExcludedElementsTableModel(enableable);
        JComponent excludedElementsPanel =
                enableable
                        ? new OptionsPanel(excludedElementsModel)
                        : new NonEnabledOptionsPanel(excludedElementsModel);
        label.setLabelFor(excludedElementsPanel);
        panel.add(excludedElementsPanel);
    }

    /**
     * Gets the UI panel.
     *
     * @return the panel.
     */
    public JPanel getPanel() {
        return panel;
    }

    /**
     * Sets the excluded elements.
     *
     * @param excludedElements the excluded elements.
     */
    public void setElements(List<ExcludedElement> excludedElements) {
        excludedElementsModel.setElements(excludedElements);
    }

    /**
     * Gets the excluded elements.
     *
     * @return the excluded elements.
     */
    public List<ExcludedElement> getElements() {
        return excludedElementsModel.getElements();
    }

    private <T> ExcludedElement showAddDialogue(
            AbstractMultipleOptionsBaseTableModel<ExcludedElement> model) {
        if (addDialog == null) {
            addDialog = new DialogAddExcludedElement(parent);
            addDialog.setEnableable(enableable);
            addDialog.pack();
        }
        addDialog.setElems(model.getElements());
        addDialog.setVisible(true);

        ExcludedElement elem = addDialog.getElem();
        addDialog.clear();
        return elem;
    }

    private <T> ExcludedElement showModifyDialogue(
            AbstractMultipleOptionsBaseTableModel<ExcludedElement> model, ExcludedElement e) {
        if (modifyDialog == null) {
            modifyDialog = new DialogModifyExcludedElement(parent);
            modifyDialog.setEnableable(enableable);
            modifyDialog.pack();
        }
        modifyDialog.setElems(model.getElements());
        modifyDialog.setElem(e);
        modifyDialog.setVisible(true);

        ExcludedElement elem = modifyDialog.getElem();
        modifyDialog.clear();

        if (!elem.equals(e)) {
            return elem;
        }

        return null;
    }

    private <T> boolean showRemoveDialogue(AbstractMultipleOptionsBaseTablePanel<T> optionsPanel) {
        JCheckBox removeWithoutConfirmationCheckBox =
                new JCheckBox(
                        Constant.messages.getString(
                                "spiderajax.excludedelements.ui.remove.checkbox.label"));
        Object[] messages = {
            Constant.messages.getString("spiderajax.excludedelements.ui.remove.text"),
            " ",
            removeWithoutConfirmationCheckBox
        };
        int option =
                JOptionPane.showOptionDialog(
                        parent,
                        messages,
                        Constant.messages.getString("spiderajax.excludedelements.ui.remove.title"),
                        JOptionPane.OK_CANCEL_OPTION,
                        JOptionPane.QUESTION_MESSAGE,
                        null,
                        new String[] {
                            Constant.messages.getString(
                                    "spiderajax.excludedelements.ui.remove.button.confirm"),
                            Constant.messages.getString(
                                    "spiderajax.excludedelements.ui.remove.button.cancel")
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
            extends AbstractMultipleOptionsBaseTablePanel<ExcludedElement> {

        private static final long serialVersionUID = 1L;

        public NonEnabledOptionsPanel(ExcludedElementsTableModel model) {
            super(model);

            getTable().setSortOrder(0, SortOrder.ASCENDING);
            getTable().setVisibleRowCount(5);
        }

        @Override
        public ExcludedElement showAddDialogue() {
            return ExcludedElementsPanel.this.showAddDialogue(getMultipleOptionsModel());
        }

        @Override
        public ExcludedElement showModifyDialogue(ExcludedElement e) {
            return ExcludedElementsPanel.this.showModifyDialogue(getMultipleOptionsModel(), e);
        }

        @Override
        public boolean showRemoveDialogue(ExcludedElement e) {
            return ExcludedElementsPanel.this.showRemoveDialogue(this);
        }
    }

    private class OptionsPanel extends AbstractMultipleOptionsTablePanel<ExcludedElement> {

        private static final long serialVersionUID = 1L;

        public OptionsPanel(ExcludedElementsTableModel model) {
            super(model);

            getTable().getColumnExt(0).setPreferredWidth(5);
            getTable().setSortOrder(1, SortOrder.ASCENDING);
            getTable().setVisibleRowCount(5);
        }

        @Override
        public ExcludedElement showAddDialogue() {
            return ExcludedElementsPanel.this.showAddDialogue(getMultipleOptionsModel());
        }

        @Override
        public ExcludedElement showModifyDialogue(ExcludedElement e) {
            return ExcludedElementsPanel.this.showModifyDialogue(getMultipleOptionsModel(), e);
        }

        @Override
        public boolean showRemoveDialogue(ExcludedElement e) {
            return ExcludedElementsPanel.this.showRemoveDialogue(this);
        }
    }

    @SuppressWarnings("serial")
    private static class ExcludedElementsTableModel
            extends AbstractMultipleOptionsTableModel<ExcludedElement> {

        private static final long serialVersionUID = 1L;

        private static final List<String> COLUMN_NAMES =
                List.of(
                        Constant.messages.getString(
                                "spiderajax.excludedelements.ui.table.header.enabled"),
                        Constant.messages.getString(
                                "spiderajax.excludedelements.ui.table.header.description"));

        private final boolean enabledColumn;
        private List<ExcludedElement> elements;

        public ExcludedElementsTableModel(boolean enabledColumn) {
            this.enabledColumn = enabledColumn;

            elements = new ArrayList<>(0);
        }

        @Override
        public List<ExcludedElement> getElements() {
            return elements;
        }

        public void setElements(List<ExcludedElement> elems) {
            this.elements = new ArrayList<>(elems.size());

            for (ExcludedElement elem : elems) {
                this.elements.add(new ExcludedElement(elem));
            }

            fireTableDataChanged();
        }

        @Override
        public String getColumnName(int col) {
            return COLUMN_NAMES.get(getEffectColumnIndex(col));
        }

        @Override
        public int getColumnCount() {
            return COLUMN_NAMES.size() - (enabledColumn ? 0 : 1);
        }

        @Override
        public Class<?> getColumnClass(int c) {
            if (enabledColumn && c == 0) {
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
            return enabledColumn && columnIndex == 0;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            switch (getEffectColumnIndex(columnIndex)) {
                case 0:
                    return Boolean.valueOf(getElement(rowIndex).isEnabled());
                case 1:
                    return getElement(rowIndex).getDescription();
                default:
                    return null;
            }
        }

        private int getEffectColumnIndex(int columnIndex) {
            return enabledColumn ? columnIndex : columnIndex + 1;
        }

        @Override
        public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
            if (enabledColumn && columnIndex == 0 && aValue instanceof Boolean) {
                elements.get(rowIndex).setEnabled(((Boolean) aValue).booleanValue());
                fireTableCellUpdated(rowIndex, columnIndex);
            }
        }
    }
}
