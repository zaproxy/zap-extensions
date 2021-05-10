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
package org.zaproxy.zap.extension.fuzz.httpfuzzer.processors;

import java.awt.event.ItemEvent;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.swing.AbstractListModel;
import javax.swing.ComboBoxModel;
import javax.swing.GroupLayout;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.AbstractHttpFuzzerMessageProcessorUIPanel;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.HttpFuzzerMessageProcessorUI;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.HttpFuzzerMessageProcessorUIHandler;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.processors.UserHttpFuzzerMessageProcessorUIHandler.UserHttpFuzzerMessageProcessorUI;
import org.zaproxy.zap.extension.users.ExtensionUserManagement;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.users.User;

public class UserHttpFuzzerMessageProcessorUIHandler
        implements HttpFuzzerMessageProcessorUIHandler<
                UserHttpFuzzerMessageProcessor, UserHttpFuzzerMessageProcessorUI> {

    private final ExtensionUserManagement extensionUserManagement;

    public UserHttpFuzzerMessageProcessorUIHandler(
            ExtensionUserManagement extensionUserManagement) {
        this.extensionUserManagement = extensionUserManagement;
    }

    @Override
    public boolean isEnabled(HttpMessage message) {
        Session session = Model.getSingleton().getSession();
        List<Context> contexts =
                session.getContextsForUrl(message.getRequestHeader().getURI().toString());
        for (Context context : contexts) {
            List<User> users =
                    extensionUserManagement.getContextUserAuthManager(context.getId()).getUsers();
            if (!users.isEmpty()) {
                return true;
            }
        }
        return false;
    }

    @Override
    public boolean isDefault() {
        return false;
    }

    @Override
    public UserHttpFuzzerMessageProcessorUI createDefault() {
        return null;
    }

    @Override
    public String getName() {
        return UserHttpFuzzerMessageProcessor.NAME;
    }

    @Override
    public Class<HttpMessage> getMessageType() {
        return HttpMessage.class;
    }

    @Override
    public Class<UserHttpFuzzerMessageProcessor> getFuzzerMessageProcessorType() {
        return UserHttpFuzzerMessageProcessor.class;
    }

    @Override
    public Class<UserHttpFuzzerMessageProcessorUI> getFuzzerMessageProcessorUIType() {
        return UserHttpFuzzerMessageProcessorUI.class;
    }

    @Override
    public UserHttpFuzzerMessageProcessorUIPanel createPanel() {
        return new UserHttpFuzzerMessageProcessorUIPanel(extensionUserManagement);
    }

    public static class UserHttpFuzzerMessageProcessorUI
            implements HttpFuzzerMessageProcessorUI<UserHttpFuzzerMessageProcessor> {

        private final User user;

        public UserHttpFuzzerMessageProcessorUI(User user) {
            this.user = user;
        }

        public User getUser() {
            return user;
        }

        @Override
        public boolean isMutable() {
            return true;
        }

        @Override
        public String getName() {
            return UserHttpFuzzerMessageProcessor.NAME;
        }

        @Override
        public String getDescription() {
            return Constant.messages.getString(
                    "fuzz.httpfuzzer.processor.userMessageProcessor.description",
                    user.getName(),
                    Integer.toString(user.getContextId()));
        }

        @Override
        public UserHttpFuzzerMessageProcessor getFuzzerMessageProcessor() {
            return new UserHttpFuzzerMessageProcessor(user);
        }

        @Override
        public UserHttpFuzzerMessageProcessorUI copy() {
            return this;
        }
    }

    public static class UserHttpFuzzerMessageProcessorUIPanel
            extends AbstractHttpFuzzerMessageProcessorUIPanel<
                    UserHttpFuzzerMessageProcessor, UserHttpFuzzerMessageProcessorUI> {

        private static final String CONTEXT_FIELD_LABEL =
                Constant.messages.getString(
                        "fuzz.httpfuzzer.processor.userMessageProcessor.panel.context.label");

        private static final String USER_FIELD_LABEL =
                Constant.messages.getString(
                        "fuzz.httpfuzzer.processor.userMessageProcessor.panel.user.label");

        private final ExtensionUserManagement extensionUserManagement;

        private final JComboBox<ContextUI> contextsComboBox;
        private final JComboBox<UserUI> usersComboBox;

        private final JPanel fieldsPanel;

        public UserHttpFuzzerMessageProcessorUIPanel(
                ExtensionUserManagement extensionUserManagement) {
            this.extensionUserManagement = extensionUserManagement;

            contextsComboBox = new JComboBox<>();
            contextsComboBox.addItem(ContextUI.NO_CONTEXT);
            usersComboBox = new JComboBox<>(ContextUI.NO_CONTEXT);

            contextsComboBox.addItemListener(
                    e -> {
                        if (ItemEvent.SELECTED == e.getStateChange()) {
                            usersComboBox.setModel((ContextUI) e.getItem());
                        }
                    });

            fieldsPanel = new JPanel();

            GroupLayout layout = new GroupLayout(fieldsPanel);
            fieldsPanel.setLayout(layout);
            layout.setAutoCreateGaps(true);

            JLabel contextsLabel = new JLabel(CONTEXT_FIELD_LABEL);
            contextsLabel.setLabelFor(contextsComboBox);

            JLabel usersLabel = new JLabel(USER_FIELD_LABEL);
            usersLabel.setLabelFor(usersComboBox);

            layout.setHorizontalGroup(
                    layout.createSequentialGroup()
                            .addGroup(
                                    layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                                            .addComponent(contextsLabel)
                                            .addComponent(usersLabel))
                            .addGroup(
                                    layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                            .addComponent(contextsComboBox)
                                            .addComponent(usersComboBox)));

            layout.setVerticalGroup(
                    layout.createSequentialGroup()
                            .addGroup(
                                    layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                            .addComponent(contextsLabel)
                                            .addComponent(contextsComboBox))
                            .addGroup(
                                    layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                            .addComponent(usersLabel)
                                            .addComponent(usersComboBox)));
        }

        @Override
        public void init(HttpMessage message) {
            Session session = Model.getSingleton().getSession();
            List<Context> contexts =
                    session.getContextsForUrl(message.getRequestHeader().getURI().toString());
            for (Context context : contexts) {
                List<User> users =
                        extensionUserManagement
                                .getContextUserAuthManager(context.getId())
                                .getUsers();
                if (!users.isEmpty()) {
                    contextsComboBox.addItem(new ContextUI(context, users));
                }
            }
        }

        @Override
        public void clear() {
            contextsComboBox.removeAllItems();
        }

        @Override
        public JPanel getComponent() {
            return fieldsPanel;
        }

        @Override
        public void setFuzzerMessageProcessorUI(
                UserHttpFuzzerMessageProcessorUI messageProcessorUI) {
            User user = messageProcessorUI.getUser();
            if (setSelectedContext(user.getContextId())) {
                setSelectedUser(user);
            }
        }

        @Override
        public boolean validate() {
            if (getSelectedUser() != null) {
                return true;
            }

            JOptionPane.showMessageDialog(
                    null,
                    Constant.messages.getString(
                            "fuzz.httpfuzzer.processor.userMessageProcessor.panel.validation.dialog.message"),
                    Constant.messages.getString(
                            "fuzz.httpfuzzer.processor.userMessageProcessor.panel.validation.dialog.title"),
                    JOptionPane.INFORMATION_MESSAGE);
            contextsComboBox.requestFocusInWindow();
            return false;
        }

        private User getSelectedUser() {
            UserUI userUI = (UserUI) usersComboBox.getSelectedItem();
            User user = (userUI != null) ? userUI.getUser() : null;
            return user;
        }

        @Override
        public UserHttpFuzzerMessageProcessorUI getFuzzerMessageProcessorUI() {
            return new UserHttpFuzzerMessageProcessorUI(getSelectedUser());
        }

        private boolean setSelectedContext(int contextId) {
            for (int i = 0; i < contextsComboBox.getModel().getSize(); i++) {
                if (contextId == contextsComboBox.getModel().getElementAt(i).getId()) {
                    contextsComboBox.setSelectedIndex(i);
                    return true;
                }
            }
            return false;
        }

        private void setSelectedUser(User user) {
            for (int i = 0; i < usersComboBox.getModel().getSize(); i++) {
                if (user == usersComboBox.getModel().getElementAt(i).getUser()) {
                    usersComboBox.setSelectedIndex(i);
                }
            }
        }
    }

    private static class ContextUI extends AbstractListModel<UserUI>
            implements ComboBoxModel<UserUI> {

        private static final long serialVersionUID = -6749757786536820094L;

        public static final ContextUI NO_CONTEXT = new ContextUI();

        private final Context context;
        private final List<UserUI> users;
        private UserUI selectedUser;

        public ContextUI(Context context, List<User> users) {
            this.context = context;
            this.users = new ArrayList<>(users.size());
            for (User user : users) {
                this.users.add(new UserUI(user));
            }
        }

        private ContextUI() {
            this.context = null;
            this.users = Collections.emptyList();
        }

        public int getId() {
            return this.context.getId();
        }

        @Override
        public String toString() {
            if (context == null) {
                return "";
            }
            return context.getName();
        }

        @Override
        public int getSize() {
            return users.size();
        }

        @Override
        public UserUI getElementAt(int index) {
            return users.get(index);
        }

        @Override
        public void setSelectedItem(Object anItem) {
            selectedUser = (UserUI) anItem;
        }

        @Override
        public UserUI getSelectedItem() {
            return selectedUser;
        }
    }

    private static class UserUI {

        private final User user;

        public UserUI(User user) {
            this.user = user;
        }

        public User getUser() {
            return user;
        }

        @Override
        public String toString() {
            return user.getName();
        }
    }
}
