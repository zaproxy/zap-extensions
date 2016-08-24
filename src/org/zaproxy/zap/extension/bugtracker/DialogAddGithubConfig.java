/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP Development Team
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); 
 * you may not use this file except in compliance with the License. 
 * You may obtain a copy of the License at 
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0 
 *   
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS, 
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
 * See the License for the specific language governing permissions and 
 * limitations under the License. 
 */
package org.zaproxy.zap.extension.bugtracker;

import java.awt.Dialog;
import java.util.List;

import javax.swing.GroupLayout;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import org.parosproxy.paros.Constant;
import org.zaproxy.zap.utils.ZapTextField;
import org.zaproxy.zap.view.AbstractFormDialog;

class DialogAddGithubConfig extends AbstractFormDialog {

    private static final long serialVersionUID = 4460797449668634319L;

    private static final String DIALOG_TITLE = Constant.messages.getString("bugtracker.trackers.github.dialog.config.add.title");
    
    private static final String CONFIRM_BUTTON_LABEL = Constant.messages.getString("bugtracker.trackers.github.dialog.config.add.button.confirm");
    
    private static final String NAME_FIELD_LABEL = Constant.messages.getString("bugtracker.trackers.github.dialog.config.field.label.name");
    private static final String PASSWORD_FIELD_LABEL = Constant.messages.getString("bugtracker.trackers.github.dialog.config.field.label.password");
    private static final String REPO_URL_FIELD_LABEL = Constant.messages.getString("bugtracker.trackers.github.dialog.config.field.label.repoUrl");
    
    private static final String TITLE_NAME_REPEATED_DIALOG = Constant.messages.getString("bugtracker.trackers.github.dialog.config.warning.name.repeated.title");
    private static final String TEXT_NAME_REPEATED_DIALOG = Constant.messages.getString("bugtracker.trackers.github.dialog.config.warning.name.repeated.text");
    
    private ZapTextField nameTextField;
    private JPasswordField passwordTextField;
    private ZapTextField repoUrlTextField;
    
    protected BugTrackerGithubConfigParams config;
    private List<BugTrackerGithubConfigParams> configs;
    
    public DialogAddGithubConfig(Dialog owner) {
        super(owner, DIALOG_TITLE);
    }
    
    protected DialogAddGithubConfig(Dialog owner, String title) {
        super(owner, title);
    }
    
    @Override
    protected JPanel getFieldsPanel() {
        JPanel fieldsPanel = new JPanel();
        
        GroupLayout layout = new GroupLayout(fieldsPanel);
        fieldsPanel.setLayout(layout);
        layout.setAutoCreateGaps(true);
        layout.setAutoCreateContainerGaps(true);
        
        JLabel nameLabel = new JLabel(NAME_FIELD_LABEL);
        JLabel passwordLabel = new JLabel(PASSWORD_FIELD_LABEL);
        JLabel repoUrlLabel = new JLabel(REPO_URL_FIELD_LABEL);
        
        layout.setHorizontalGroup(layout.createSequentialGroup()
            .addGroup(layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                .addComponent(nameLabel)
                .addComponent(passwordLabel)
                .addComponent(repoUrlLabel))
            .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                .addComponent(getNameTextField())
                .addComponent(getPasswordTextField())
                .addComponent(getRepoUrlTextField()))
        );
        
        layout.setVerticalGroup(layout.createSequentialGroup()
            .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                .addComponent(nameLabel)
                .addComponent(getNameTextField()))
            .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                .addComponent(passwordLabel)
                .addComponent(getPasswordTextField()))
            .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                .addComponent(repoUrlLabel)
                .addComponent(getRepoUrlTextField()))
        );
        
        return fieldsPanel;
    }
    
    @Override
    protected String getConfirmButtonLabel() {
        return CONFIRM_BUTTON_LABEL;
    }
    
    @Override
    protected void init() {
        getNameTextField().setText("");
        getPasswordTextField().setText("");
        getRepoUrlTextField().setText("");
        config = null;
    }

    @Override
    protected boolean validateFields() {
        String configName = getNameTextField().getText();
        for (BugTrackerGithubConfigParams t : configs) {
            if (configName.equalsIgnoreCase(t.getName())) {
                JOptionPane.showMessageDialog(this, TEXT_NAME_REPEATED_DIALOG,
                        TITLE_NAME_REPEATED_DIALOG,
                        JOptionPane.INFORMATION_MESSAGE);
                getNameTextField().requestFocusInWindow();
                return false;
            }
        }
        
        return true;
    }
    
    @Override
    protected void performAction() {
        config = new BugTrackerGithubConfigParams(getNameTextField().getText(), getPasswordTextField().getText(), getRepoUrlTextField().getText());
    }
    
    @Override
    protected void clearFields() {
        getNameTextField().setText("");
        getNameTextField().discardAllEdits();
        getPasswordTextField().setText("");
        getRepoUrlTextField().setText("");
        getRepoUrlTextField().discardAllEdits();
    }

    public BugTrackerGithubConfigParams getConfig() {
        return config;
    }
    
    protected ZapTextField getNameTextField() {
        if (nameTextField == null) {
            nameTextField = new ZapTextField(25);
            nameTextField.getDocument().addDocumentListener(new DocumentListener() {
                
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
                    setConfirmButtonEnabled(getNameTextField().getDocument().getLength() > 0);
                }
            });
        }
        
        return nameTextField;
    }
        
    protected JPasswordField getPasswordTextField() {
        if (passwordTextField == null) {
            passwordTextField = new JPasswordField(50);
            passwordTextField.getDocument().addDocumentListener(new DocumentListener() {
                
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
                    setConfirmButtonEnabled(getPasswordTextField().getDocument().getLength() > 0);
                }
            });
        }
        
        return passwordTextField;
    }
        
    protected ZapTextField getRepoUrlTextField() {
        if (repoUrlTextField == null) {
            repoUrlTextField = new ZapTextField(100);
            repoUrlTextField.getDocument().addDocumentListener(new DocumentListener() {
                
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
                    setConfirmButtonEnabled(getRepoUrlTextField().getDocument().getLength() > 0);
                }
            });
        }
        
        return repoUrlTextField;
    }

    public void setConfigs(List<BugTrackerGithubConfigParams> configs) {
        this.configs = configs;
    }

    public void clear() {
        this.configs =  null;
        this.config = null;
    }
    
}
