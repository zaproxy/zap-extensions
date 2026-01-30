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
package org.zaproxy.zap.extension.selenium.internal;

import java.awt.Dialog;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import javax.swing.GroupLayout;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.utils.ZapTextField;
import org.zaproxy.zap.view.AbstractFormDialog;

@SuppressWarnings("serial")
public class DialogCustomBrowser extends AbstractFormDialog {

    private static final long serialVersionUID = 1L;

    private ZapTextField nameTextField;
    private JTextField driverPathTextField;
    private JButton driverPathButton;
    private JTextField binaryPathTextField;
    private JButton binaryPathButton;
    private JComboBox<CustomBrowserImpl.BrowserType> browserTypeCombo;
    private BrowserArgumentsDialog argumentsDialog;
    private BrowserArgumentsTableModel argumentsTableModel;
    private JTextField argumentsTextField;
    private JButton argumentsButton;

    protected CustomBrowserImpl customBrowser;
    private List<CustomBrowserImpl> existingBrowsers;
    private String originalName;

    public DialogCustomBrowser(Dialog owner, String title) {
        super(owner, title);
        argumentsTableModel = new BrowserArgumentsTableModel();
        argumentsDialog =
                new BrowserArgumentsDialog(
                        owner,
                        argumentsTableModel,
                        new java.util.concurrent.atomic.AtomicBoolean());
    }

    @Override
    protected JPanel getFieldsPanel() {
        JPanel fieldsPanel = new JPanel();

        GroupLayout layout = new GroupLayout(fieldsPanel);
        fieldsPanel.setLayout(layout);
        layout.setAutoCreateGaps(true);
        layout.setAutoCreateContainerGaps(true);

        JLabel nameLabel = createLabel("name", getNameTextField());
        JLabel driverPathLabel = createLabel("driver", getDriverPathTextField());
        JLabel binaryPathLabel = createLabel("binary", getBinaryPathTextField());
        JLabel browserTypeLabel = createLabel("type", getBrowserTypeCombo());
        JLabel argumentsLabel = createLabel("args", getArgumentsTextField());

        layout.setHorizontalGroup(
                layout.createSequentialGroup()
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                                        .addComponent(nameLabel)
                                        .addComponent(driverPathLabel)
                                        .addComponent(binaryPathLabel)
                                        .addComponent(browserTypeLabel)
                                        .addComponent(argumentsLabel))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                        .addComponent(getNameTextField())
                                        .addComponent(getDriverPathTextField())
                                        .addComponent(getBinaryPathTextField())
                                        .addComponent(getBrowserTypeCombo())
                                        .addComponent(getArgumentsTextField()))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                        .addComponent(getDriverPathButton())
                                        .addComponent(getBinaryPathButton())
                                        .addComponent(getArgumentsButton())));

        layout.setVerticalGroup(
                layout.createSequentialGroup()
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(nameLabel)
                                        .addComponent(getNameTextField()))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(driverPathLabel)
                                        .addComponent(getDriverPathTextField())
                                        .addComponent(getDriverPathButton()))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(binaryPathLabel)
                                        .addComponent(getBinaryPathTextField())
                                        .addComponent(getBinaryPathButton()))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(browserTypeLabel)
                                        .addComponent(getBrowserTypeCombo()))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(argumentsLabel)
                                        .addComponent(getArgumentsTextField())
                                        .addComponent(getArgumentsButton())));

        setConfirmButtonEnabled(false);

        return fieldsPanel;
    }

    private static JLabel createLabel(String key, JComponent field) {
        JLabel label =
                new JLabel(
                        Constant.messages.getString(
                                "selenium.options.custom.browsers.field." + key));
        label.setLabelFor(field);
        return label;
    }

    @Override
    protected String getConfirmButtonLabel() {
        return Constant.messages.getString("selenium.options.custom.browsers.button.add");
    }

    @Override
    protected void init() {
        CustomBrowserImpl browserToPopulate = customBrowser;
        reset(getNameTextField());
        reset(getDriverPathTextField());
        reset(getBinaryPathTextField());
        getBrowserTypeCombo().setSelectedItem(CustomBrowserImpl.BrowserType.CHROMIUM);
        argumentsTableModel.setArguments(new ArrayList<>());
        updateArgumentsDisplay();
        originalName = null;

        // If we have a browser to populate (for modify), populate it now
        if (browserToPopulate != null) {
            populateFromBrowser(browserToPopulate);
        } else {
            customBrowser = null;
        }
    }

    private void populateFromBrowser(CustomBrowserImpl browser) {
        if (browser != null) {
            originalName = browser.getName();
            getNameTextField().setText(browser.getName());
            getNameTextField().setEditable(!browser.isBuiltIn());
            getDriverPathTextField().setText(browser.getDriverPath());
            getBinaryPathTextField().setText(browser.getBinaryPath());
            getBrowserTypeCombo().setSelectedItem(browser.getBrowserType());
            getBrowserTypeCombo().setEnabled(!browser.isBuiltIn());
            argumentsTableModel.setArguments(browser.getArguments());
            updateArgumentsDisplay();
            setConfirmButtonEnabled(true);
        }
    }

    @Override
    protected boolean validateFields() {
        String name = getNameTextField().getText().trim();
        if (name.isEmpty()) {
            JOptionPane.showMessageDialog(
                    this,
                    Constant.messages.getString(
                            "selenium.options.custom.browsers.error.name.empty"),
                    Constant.messages.getString("selenium.options.custom.browsers.error.title"),
                    JOptionPane.WARNING_MESSAGE);
            getNameTextField().requestFocusInWindow();
            return false;
        }

        // Check for duplicate names (excluding the current one if editing)
        if (existingBrowsers != null) {
            for (CustomBrowserImpl browser : existingBrowsers) {
                if (name.equals(browser.getName())
                        && (originalName == null || !name.equals(originalName))) {
                    JOptionPane.showMessageDialog(
                            this,
                            Constant.messages.getString(
                                    "selenium.options.custom.browsers.error.name.duplicate"),
                            Constant.messages.getString(
                                    "selenium.options.custom.browsers.error.title"),
                            JOptionPane.WARNING_MESSAGE);
                    getNameTextField().requestFocusInWindow();
                    return false;
                }
            }
        }

        return true;
    }

    @Override
    protected void performAction() {
        boolean isBuiltIn = customBrowser != null && customBrowser.isBuiltIn();
        customBrowser =
                new CustomBrowserImpl(
                        getNameTextField().getText().trim(),
                        getDriverPathTextField().getText().trim(),
                        getBinaryPathTextField().getText().trim(),
                        (CustomBrowserImpl.BrowserType) getBrowserTypeCombo().getSelectedItem(),
                        argumentsTableModel.getElements());
        // Explicitly set builtIn flag - preserve for modify, false for add
        customBrowser.setBuiltIn(isBuiltIn);
    }

    @Override
    protected void clearFields() {
        reset(getNameTextField());
        reset(getDriverPathTextField());
        reset(getBinaryPathTextField());
        getBrowserTypeCombo().setSelectedItem(CustomBrowserImpl.BrowserType.CHROMIUM);
        argumentsTableModel.setArguments(new ArrayList<>());
        updateArgumentsDisplay();
    }

    private static void reset(JTextField textField) {
        textField.setText("");
    }

    public CustomBrowserImpl getCustomBrowser() {
        return customBrowser;
    }

    public void setCustomBrowser(CustomBrowserImpl browser) {
        this.customBrowser = browser;
        // Fields will be populated in init() when dialog is shown
    }

    public void setExistingBrowsers(List<CustomBrowserImpl> browsers) {
        this.existingBrowsers = browsers;
    }

    protected ZapTextField getNameTextField() {
        if (nameTextField == null) {
            nameTextField = new ZapTextField(25);
            nameTextField
                    .getDocument()
                    .addDocumentListener(
                            new DocumentListener() {
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
                                            getNameTextField().getDocument().getLength() > 0);
                                }
                            });
        }
        return nameTextField;
    }

    protected JTextField getDriverPathTextField() {
        if (driverPathTextField == null) {
            driverPathTextField = new JTextField(25);
        }
        return driverPathTextField;
    }

    protected JButton getDriverPathButton() {
        if (driverPathButton == null) {
            driverPathButton =
                    new JButton(
                            Constant.messages.getString(
                                    "selenium.options.label.button.select.file"));
            driverPathButton.addActionListener(
                    e -> {
                        JFileChooser fileChooser = new JFileChooser();
                        String path = getDriverPathTextField().getText();
                        if (path != null && !path.isEmpty()) {
                            File file = new File(path);
                            if (file.exists()) {
                                fileChooser.setSelectedFile(file);
                            }
                        }
                        if (fileChooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
                            getDriverPathTextField()
                                    .setText(fileChooser.getSelectedFile().getAbsolutePath());
                        }
                    });
        }
        return driverPathButton;
    }

    protected JTextField getBinaryPathTextField() {
        if (binaryPathTextField == null) {
            binaryPathTextField = new JTextField(25);
        }
        return binaryPathTextField;
    }

    protected JButton getBinaryPathButton() {
        if (binaryPathButton == null) {
            binaryPathButton =
                    new JButton(
                            Constant.messages.getString(
                                    "selenium.options.label.button.select.file"));
            binaryPathButton.addActionListener(
                    e -> {
                        JFileChooser fileChooser = new JFileChooser();
                        String path = getBinaryPathTextField().getText();
                        if (path != null && !path.isEmpty()) {
                            File file = new File(path);
                            if (file.exists()) {
                                fileChooser.setSelectedFile(file);
                            }
                        }
                        if (fileChooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
                            getBinaryPathTextField()
                                    .setText(fileChooser.getSelectedFile().getAbsolutePath());
                        }
                    });
        }
        return binaryPathButton;
    }

    protected JComboBox<CustomBrowserImpl.BrowserType> getBrowserTypeCombo() {
        if (browserTypeCombo == null) {
            browserTypeCombo = new JComboBox<>(CustomBrowserImpl.BrowserType.values());
        }
        return browserTypeCombo;
    }

    protected JTextField getArgumentsTextField() {
        if (argumentsTextField == null) {
            argumentsTextField = new JTextField(25);
            argumentsTextField.setEditable(false);
        }
        return argumentsTextField;
    }

    protected JButton getArgumentsButton() {
        if (argumentsButton == null) {
            argumentsButton =
                    new JButton(
                            Constant.messages.getString("selenium.options.label.button.configure"));
            argumentsButton.addActionListener(
                    e -> {
                        argumentsDialog.setVisible(true);
                        updateArgumentsDisplay();
                    });
        }
        return argumentsButton;
    }

    private void updateArgumentsDisplay() {
        argumentsTextField.setText(argumentsTableModel.getArgumentsAsString());
        argumentsTextField.setCaretPosition(0);
    }

    public void clear() {
        this.existingBrowsers = null;
        this.customBrowser = null;
        this.originalName = null;
    }
}
