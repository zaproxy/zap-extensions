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
package org.zaproxy.zap.extension.alertFilters.internal.ui;

import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;
import javax.swing.DefaultListModel;
import javax.swing.GroupLayout;
import javax.swing.GroupLayout.Alignment;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextField;
import javax.swing.ListModel;
import javax.swing.ScrollPaneConstants;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.zap.utils.SortedListModel;
import org.zaproxy.zap.utils.ZapTextField;
import org.zaproxy.zap.view.AbstractFormDialog;

public class MethodSelectionPanel {

    private static final List<String> DEFAULT_METHODS = List.of(HttpRequestHeader.METHODS);

    private final JLabel label;
    private final JTextField methodsTexField;
    private final JButton methodsButton;
    private final JPanel fieldComponent;
    private SelectionDialogue dialogue;

    public MethodSelectionPanel(JDialog parent) {
        dialogue = new SelectionDialogue(parent);
        dialogue.pack();

        label = new JLabel(Constant.messages.getString("alertFilters.dialog.methods.label.method"));

        methodsTexField = new JTextField();
        methodsTexField.setEditable(false);
        methodsButton =
                new JButton(
                        Constant.messages.getString("alertFilters.dialog.methods.button.select"));
        methodsButton.addActionListener(
                e -> {
                    dialogue.setMethods(getMethods());
                    dialogue.setVisible(true);
                    updateMethodsTextField(dialogue.getMethods());
                });

        fieldComponent = new JPanel();
        GroupLayout layout = new GroupLayout(fieldComponent);
        fieldComponent.setLayout(layout);
        layout.setAutoCreateGaps(true);

        layout.setHorizontalGroup(
                layout.createSequentialGroup()
                        .addComponent(methodsTexField)
                        .addComponent(methodsButton));

        layout.setVerticalGroup(
                layout.createParallelGroup()
                        .addComponent(methodsTexField)
                        .addComponent(methodsButton));

        label.setLabelFor(fieldComponent);
    }

    public JLabel getLabel() {
        return label;
    }

    public JComponent getFieldComponent() {
        return fieldComponent;
    }

    public Set<String> getMethods() {
        return dialogue.getMethods();
    }

    public void setMethods(Set<String> methods) {
        updateMethodsTextField(methods);
        dialogue.setMethods(methods);
    }

    private void updateMethodsTextField(Set<String> methods) {
        if (methods == null) {
            methodsTexField.setText("");
            return;
        }

        methodsTexField.setText(methods.stream().collect(Collectors.joining(", ")));
    }

    public void reset() {
        methodsTexField.setText("");
        dialogue.setMethods(Set.of());
    }

    @SuppressWarnings("serial")
    private static class SelectionDialogue extends AbstractFormDialog {

        private JPanel fieldsPanel;

        private ZapTextField customMethodTextField;
        private DefaultListModel<String> defaultMethodsListModel;
        private JList<String> defaultMethodsList;
        private DefaultListModel<String> selectedMethodsListModel;
        private JList<String> selectedMethodsList;

        private Set<String> methods;

        public SelectionDialogue(JDialog parent) {
            super(parent, Constant.messages.getString("alertFilters.dialog.methods.title"));

            setConfirmButtonEnabled(true);
        }

        @Override
        protected void performAction() {
            methods = listModelToSet(selectedMethodsListModel);
        }

        public Set<String> getMethods() {
            return methods;
        }

        private static Set<String> listModelToSet(ListModel<String> model) {
            Set<String> set = new TreeSet<>();
            for (int i = 0; i < model.getSize(); i++) {
                set.add(model.getElementAt(i));
            }
            return set;
        }

        @Override
        public void setVisible(boolean b) {
            reset();
            if (b) {
                methods.forEach(
                        e -> {
                            defaultMethodsListModel.removeElement(e);
                            selectedMethodsListModel.addElement(e);
                        });
            }

            super.setVisible(b);
        }

        public void setMethods(Set<String> methods) {
            this.methods = methods == null ? Set.of() : methods;
        }

        void reset() {
            customMethodTextField.setText("");
            customMethodTextField.discardAllEdits();
            defaultMethodsList.clearSelection();
            defaultMethodsListModel.removeAllElements();
            DEFAULT_METHODS.forEach(defaultMethodsListModel::addElement);
            selectedMethodsList.clearSelection();
            selectedMethodsListModel.removeAllElements();
        }

        @Override
        protected JPanel getFieldsPanel() {
            if (fieldsPanel == null) {
                customMethodTextField = new ZapTextField();
                JLabel customMethodLabel =
                        new JLabel(
                                Constant.messages.getString(
                                        "alertFilters.dialog.methods.label.custom"));
                customMethodLabel.setLabelFor(customMethodTextField);
                JButton addCustomMethod =
                        new JButton(
                                Constant.messages.getString(
                                        "alertFilters.dialog.methods.button.add"));
                addCustomMethod.setEnabled(false);

                JLabel defaultMethodsLabel =
                        new JLabel(
                                Constant.messages.getString(
                                        "alertFilters.dialog.methods.label.default"));
                defaultMethodsListModel = new SortedListModel<>();
                defaultMethodsList = new JList<>(defaultMethodsListModel);
                defaultMethodsList.setVisibleRowCount(10);
                defaultMethodsLabel.setLabelFor(defaultMethodsList);
                JScrollPane defaultMethodsListScrollPane = new JScrollPane(defaultMethodsList);
                defaultMethodsListScrollPane.setHorizontalScrollBarPolicy(
                        ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);

                JButton addDefault = new JButton(">>>");
                addDefault.setEnabled(false);
                JButton removeMethod = new JButton("<<<");
                removeMethod.setEnabled(false);

                JLabel selectedMethodsLabel =
                        new JLabel(
                                Constant.messages.getString(
                                        "alertFilters.dialog.methods.label.selected"));
                selectedMethodsListModel = new SortedListModel<>();
                selectedMethodsList = new JList<>(selectedMethodsListModel);
                selectedMethodsList.setVisibleRowCount(10);
                selectedMethodsLabel.setLabelFor(selectedMethodsList);
                JScrollPane selectedMethodsListScrollPane = new JScrollPane(selectedMethodsList);
                selectedMethodsListScrollPane.setHorizontalScrollBarPolicy(
                        ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);

                fieldsPanel = new JPanel();
                GroupLayout layout = new GroupLayout(fieldsPanel);
                fieldsPanel.setLayout(layout);
                layout.setAutoCreateGaps(true);
                layout.setAutoCreateContainerGaps(true);

                layout.setHorizontalGroup(
                        layout.createParallelGroup()
                                .addGroup(
                                        layout.createSequentialGroup()
                                                .addComponent(customMethodLabel)
                                                .addComponent(customMethodTextField)
                                                .addComponent(addCustomMethod))
                                .addGroup(
                                        layout.createSequentialGroup()
                                                .addGroup(
                                                        layout.createParallelGroup()
                                                                .addComponent(defaultMethodsLabel)
                                                                .addComponent(
                                                                        defaultMethodsListScrollPane))
                                                .addGroup(
                                                        layout.createParallelGroup()
                                                                .addComponent(addDefault)
                                                                .addComponent(removeMethod))
                                                .addGroup(
                                                        layout.createParallelGroup()
                                                                .addComponent(selectedMethodsLabel)
                                                                .addComponent(
                                                                        selectedMethodsListScrollPane))));

                layout.setVerticalGroup(
                        layout.createSequentialGroup()
                                .addGroup(
                                        layout.createParallelGroup()
                                                .addComponent(customMethodLabel)
                                                .addComponent(
                                                        customMethodTextField,
                                                        GroupLayout.PREFERRED_SIZE,
                                                        GroupLayout.PREFERRED_SIZE,
                                                        GroupLayout.PREFERRED_SIZE)
                                                .addComponent(addCustomMethod))
                                .addGroup(
                                        layout.createParallelGroup()
                                                .addGroup(
                                                        layout.createSequentialGroup()
                                                                .addComponent(defaultMethodsLabel)
                                                                .addComponent(
                                                                        defaultMethodsListScrollPane))
                                                .addGroup(
                                                        Alignment.CENTER,
                                                        layout.createSequentialGroup()
                                                                .addComponent(addDefault)
                                                                .addComponent(removeMethod))
                                                .addGroup(
                                                        layout.createSequentialGroup()
                                                                .addComponent(selectedMethodsLabel)
                                                                .addComponent(
                                                                        selectedMethodsListScrollPane))));

                customMethodTextField
                        .getDocument()
                        .addDocumentListener(
                                new DocumentListener() {

                                    @Override
                                    public void removeUpdate(DocumentEvent e) {
                                        updateButton(e);
                                    }

                                    @Override
                                    public void insertUpdate(DocumentEvent e) {
                                        updateButton(e);
                                    }

                                    @Override
                                    public void changedUpdate(DocumentEvent e) {
                                        updateButton(e);
                                    }

                                    private void updateButton(DocumentEvent e) {
                                        addCustomMethod.setEnabled(
                                                e.getDocument().getLength() != 0);
                                    }
                                });

                addCustomMethod.addActionListener(
                        e -> {
                            String method =
                                    customMethodTextField.getText().toUpperCase(Locale.ROOT);
                            if (!selectedMethodsListModel.contains(method)) {
                                selectedMethodsListModel.addElement(method);
                            }
                            customMethodTextField.setText("");
                        });

                addDefault.addActionListener(
                        e ->
                                defaultMethodsList
                                        .getSelectedValuesList()
                                        .forEach(
                                                method -> {
                                                    if (!selectedMethodsListModel.contains(
                                                            method)) {
                                                        selectedMethodsListModel.addElement(method);
                                                    }
                                                    defaultMethodsListModel.removeElement(method);
                                                }));

                removeMethod.addActionListener(
                        e ->
                                selectedMethodsList
                                        .getSelectedValuesList()
                                        .forEach(
                                                method -> {
                                                    if (!defaultMethodsListModel.contains(method)) {
                                                        defaultMethodsListModel.addElement(method);
                                                    }
                                                    selectedMethodsListModel.removeElement(method);
                                                }));

                defaultMethodsList.addListSelectionListener(
                        e -> {
                            addDefault.setEnabled(
                                    !defaultMethodsList.getSelectionModel().isSelectionEmpty());
                        });

                selectedMethodsList.addListSelectionListener(
                        e ->
                                removeMethod.setEnabled(
                                        !selectedMethodsList
                                                .getSelectionModel()
                                                .isSelectionEmpty()));
            }
            return fieldsPanel;
        }

        @Override
        protected String getConfirmButtonLabel() {
            return Constant.messages.getString("alertFilters.dialog.methods.button.save");
        }
    }
}
