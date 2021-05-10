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
package org.zaproxy.zap.extension.fuzz;

import java.awt.CardLayout;
import java.awt.Frame;
import java.awt.event.ItemEvent;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.swing.GroupLayout;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.httppanel.Message;
import org.zaproxy.zap.utils.SortedComboBoxModel;
import org.zaproxy.zap.view.AbstractFormDialog;

public class SelectMessageDialogue extends AbstractFormDialog {

    private static final long serialVersionUID = -117024736933191325L;

    private static final String DIALOG_TITLE =
            Constant.messages.getString("fuzz.select.message.dialog.title");

    private static final String CONFIRM_BUTTON_LABEL =
            Constant.messages.getString("fuzz.select.message.dialog.confirm.button");

    private static final String TYPE_FIELD_LABEL =
            Constant.messages.getString("fuzz.select.message.dialog.message.type.label");

    private JComboBox<String> messageTypesComboBox;

    private CardLayout contentsPanelCardLayout;
    private JPanel contentsPanel;

    private FuzzerHandlers messageSelectionPanels;

    private FuzzerHandlerEntry<?, ?> currentPanel;
    private Selection<?, ?> selection;

    public SelectMessageDialogue(
            Frame owner, String nameDefaultFuzzer, List<FuzzerHandler<?, ?>> fuzzerHandlers) {
        super(owner, DIALOG_TITLE, false);

        this.messageSelectionPanels = new FuzzerHandlers(fuzzerHandlers);

        currentPanel = messageSelectionPanels.getEntry(nameDefaultFuzzer);
        setHelpTarget(currentPanel.getMessageSelectorPanel().getHelpTarget());

        initView();
        getMessageTypesComboBox().setSelectedItem(nameDefaultFuzzer);

        setConfirmButtonEnabled(true);
    }

    @Override
    protected JPanel getFieldsPanel() {
        JPanel fieldsPanel = new JPanel();

        GroupLayout groupLayout = new GroupLayout(fieldsPanel);
        fieldsPanel.setLayout(groupLayout);
        groupLayout.setAutoCreateGaps(true);
        groupLayout.setAutoCreateContainerGaps(true);

        contentsPanelCardLayout = new CardLayout();
        contentsPanel = new JPanel(contentsPanelCardLayout);

        for (String messageType : messageSelectionPanels.getFuzzerHandlersNames()) {
            contentsPanel.add(
                    messageSelectionPanels
                            .getEntry(messageType)
                            .getMessageSelectorPanel()
                            .getPanel(),
                    messageType);
        }

        JLabel messageTypeLabel = new JLabel(TYPE_FIELD_LABEL);

        groupLayout.setHorizontalGroup(
                groupLayout
                        .createParallelGroup()
                        .addGroup(
                                groupLayout
                                        .createSequentialGroup()
                                        .addGroup(
                                                groupLayout
                                                        .createParallelGroup(
                                                                GroupLayout.Alignment.TRAILING)
                                                        .addComponent(messageTypeLabel))
                                        .addGroup(
                                                groupLayout
                                                        .createParallelGroup(
                                                                GroupLayout.Alignment.LEADING)
                                                        .addComponent(getMessageTypesComboBox())))
                        .addComponent(contentsPanel));

        groupLayout.setVerticalGroup(
                groupLayout
                        .createSequentialGroup()
                        .addGroup(
                                groupLayout
                                        .createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(messageTypeLabel)
                                        .addComponent(getMessageTypesComboBox()))
                        .addComponent(contentsPanel));

        return fieldsPanel;
    }

    @Override
    protected String getConfirmButtonLabel() {
        return CONFIRM_BUTTON_LABEL;
    }

    @Override
    protected boolean validateFields() {
        return currentPanel.getMessageSelectorPanel().validate();
    }

    @Override
    protected void performAction() {
        selection = currentPanel.createSelection();
    }

    @Override
    protected void clearFields() {
        for (FuzzerHandlerEntry<?, ?> panel : messageSelectionPanels.getPanels()) {
            panel.getMessageSelectorPanel().clear();
        }
    }

    public Selection<?, ?> getSelection() {
        return selection;
    }

    protected JComboBox<String> getMessageTypesComboBox() {
        if (messageTypesComboBox == null) {
            messageTypesComboBox = new JComboBox<>(new SortedComboBoxModel<String>());
            for (String name : messageSelectionPanels.getFuzzerHandlersNames()) {
                messageTypesComboBox.addItem(name);
            }

            messageTypesComboBox.addItemListener(
                    e -> {
                        if (ItemEvent.SELECTED == e.getStateChange()) {
                            String panelName = (String) e.getItem();

                            currentPanel = messageSelectionPanels.getEntry(panelName);
                            contentsPanelCardLayout.show(contentsPanel, panelName);

                            setHelpTarget(currentPanel.getMessageSelectorPanel().getHelpTarget());
                        }
                    });
        }
        return messageTypesComboBox;
    }

    private static class FuzzerHandlerEntry<M extends Message, F extends Fuzzer<M>> {

        private final FuzzerHandler<M, F> fuzzerHandler;
        private final MessageSelectorPanel<M> panel;

        private FuzzerHandlerEntry(FuzzerHandler<M, F> fuzzerHandler) {
            this.fuzzerHandler = fuzzerHandler;
            this.panel = fuzzerHandler.createMessageSelectorPanel();
        }

        private MessageSelectorPanel<M> getMessageSelectorPanel() {
            return panel;
        }

        private Selection<M, F> createSelection() {
            return new Selection<>(fuzzerHandler, panel.getSelectedMessage());
        }
    }

    private static class FuzzerHandlers {

        private Map<String, FuzzerHandlerEntry<?, ?>> panels;

        public FuzzerHandlers(List<FuzzerHandler<?, ?>> fuzzerHandlers) {
            this.panels = new HashMap<>();

            for (FuzzerHandler<?, ?> fuzzerHandler : fuzzerHandlers) {
                panels.put(fuzzerHandler.getUIName(), new FuzzerHandlerEntry<>(fuzzerHandler));
            }
        }

        public Set<String> getFuzzerHandlersNames() {
            return panels.keySet();
        }

        public FuzzerHandlerEntry<?, ?> getEntry(String name) {
            return panels.get(name);
        }

        public Collection<FuzzerHandlerEntry<?, ?>> getPanels() {
            return panels.values();
        }
    }

    public static final class Selection<M extends Message, F extends Fuzzer<M>> {

        private final FuzzerHandler<M, F> fuzzerHandler;
        private final M message;

        private Selection(FuzzerHandler<M, F> fuzzerHandler, M message) {
            this.fuzzerHandler = fuzzerHandler;
            this.message = message;
        }

        public FuzzerHandler<M, F> getFuzzerHandler() {
            return fuzzerHandler;
        }

        public M getMessage() {
            return message;
        }
    }
}
