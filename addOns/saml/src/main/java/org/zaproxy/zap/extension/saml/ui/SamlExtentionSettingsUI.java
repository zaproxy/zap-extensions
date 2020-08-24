/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2013 The ZAP Development Team
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
package org.zaproxy.zap.extension.saml.ui;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.FocusEvent;
import java.awt.event.FocusListener;
import java.util.Set;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextField;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import org.apache.log4j.Logger;
import org.zaproxy.zap.extension.saml.Attribute;
import org.zaproxy.zap.extension.saml.AttributeListener;
import org.zaproxy.zap.extension.saml.PassiveAttributeChangeListener;
import org.zaproxy.zap.extension.saml.SAMLConfiguration;
import org.zaproxy.zap.extension.saml.SAMLException;
import org.zaproxy.zap.extension.saml.SamlI18n;

public class SamlExtentionSettingsUI extends JFrame
        implements PassiveAttributeChangeListener, AttributeListener {

    private static final long serialVersionUID = 1L;
    private JScrollPane settingsScrollPane;
    private JCheckBox chckbxEnablePassiveChanger;
    private JCheckBox chckbxRemoveMessageSignatures;
    private JCheckBox chckbxValidateAttributeValue;
    private JCheckBox chckbxDeflateOnSend;

    private SAMLConfiguration configuration;

    protected Logger log = Logger.getLogger(SamlExtentionSettingsUI.class.getName());

    /** Create the frame. */
    public SamlExtentionSettingsUI() {
        configuration = SAMLConfiguration.getInstance();
        setTitle(SamlI18n.getMessage("saml.toolmenu.settings"));
        setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        setSize(800, 700);
        setLocationRelativeTo(null);
        JPanel contentPane = new JPanel();
        contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
        contentPane.setLayout(new BorderLayout(0, 0));
        setContentPane(contentPane);

        JLabel lblHeaderlabel = new JLabel(SamlI18n.getMessage("saml.settings.header"));
        contentPane.add(lblHeaderlabel, BorderLayout.NORTH);

        settingsScrollPane = new JScrollPane();
        contentPane.add(settingsScrollPane, BorderLayout.CENTER);

        JPanel footerPanel = new JPanel();
        contentPane.add(footerPanel, BorderLayout.SOUTH);
        footerPanel.setLayout(new FlowLayout(FlowLayout.LEFT, 5, 5));

        JButton btnAddAutoChange =
                new JButton(SamlI18n.getMessage("saml.settings.button.addautochangeattrib"));
        btnAddAutoChange.addActionListener(
                new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        AddAutoChangeAttributeUI dialog =
                                new AddAutoChangeAttributeUI(SamlExtentionSettingsUI.this);
                        dialog.setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);
                        dialog.setVisible(true);
                    }
                });
        footerPanel.add(btnAddAutoChange);

        JButton btnAdd = new JButton(SamlI18n.getMessage("saml.settings.button.addattrib"));
        btnAdd.addActionListener(
                new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        AddAttributeUI addAttributeUI =
                                new AddAttributeUI(SamlExtentionSettingsUI.this);
                        addAttributeUI.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
                        addAttributeUI.setVisible(true);
                    }
                });
        footerPanel.add(btnAdd);

        JButton btnSaveChanges = new JButton(SamlI18n.getMessage("saml.settings.button.save"));
        btnSaveChanges.addActionListener(
                new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        boolean success = saveChanges();
                        if (success) {
                            JOptionPane.showMessageDialog(
                                    SamlExtentionSettingsUI.this,
                                    SamlI18n.getMessage("saml.settings" + ".messages.saved"),
                                    SamlI18n.getMessage("saml.settings.messages.success"),
                                    JOptionPane.INFORMATION_MESSAGE);
                        } else {
                            JOptionPane.showMessageDialog(
                                    SamlExtentionSettingsUI.this,
                                    SamlI18n.getMessage("saml.settings" + ".messages.notsaved"),
                                    SamlI18n.getMessage("saml.settings.messages.failed"),
                                    JOptionPane.ERROR_MESSAGE);
                        }
                    }
                });
        footerPanel.add(btnSaveChanges);

        JButton btnResetChanges = new JButton(SamlI18n.getMessage("saml.settings.button.reset"));
        btnResetChanges.addActionListener(
                new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        int response =
                                JOptionPane.showConfirmDialog(
                                        SamlExtentionSettingsUI.this,
                                        SamlI18n.getMessage("saml.editor.msg.confirmreset"),
                                        SamlI18n.getMessage("saml.settings.messages.confirm"),
                                        JOptionPane.YES_NO_OPTION);
                        if (response == JOptionPane.YES_OPTION) {
                            resetChanges();
                        }
                    }
                });
        footerPanel.add(btnResetChanges);

        JButton btnExit = new JButton(SamlI18n.getMessage("saml.settings.button.exit"));
        btnExit.addActionListener(
                new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        int response =
                                JOptionPane.showConfirmDialog(
                                        SamlExtentionSettingsUI.this,
                                        "Do You want to save changes before exit?",
                                        SamlI18n.getMessage("saml.settings.messages" + ".confirm"),
                                        JOptionPane.YES_NO_CANCEL_OPTION);
                        boolean exit = false;
                        if (response == JOptionPane.YES_OPTION) {
                            saveChanges();
                            exit = true;
                        } else if (response == JOptionPane.NO_OPTION) {
                            resetChanges();
                            exit = true;
                        }

                        if (exit) {
                            setVisible(false);
                            dispose();
                        }
                    }
                });
        footerPanel.add(btnExit);
        initAttributes();
    }

    /** Initialize UI with the attributes */
    private void initAttributes() {
        JPanel settingsPanel = new JPanel();
        settingsScrollPane.setViewportView(settingsPanel);
        GridBagLayout gridBagLayout = new GridBagLayout();
        settingsPanel.setLayout(gridBagLayout);

        GridBagConstraints panelConstraints = new GridBagConstraints();
        panelConstraints.anchor = GridBagConstraints.FIRST_LINE_START;
        panelConstraints.fill = GridBagConstraints.HORIZONTAL;
        panelConstraints.weightx = 1.0;
        panelConstraints.gridx = 0;
        panelConstraints.gridy = 0;
        JPanel globalSettingsPanel = new JPanel();
        globalSettingsPanel.setBorder(
                new TitledBorder(
                        null,
                        SamlI18n.getMessage("saml.settings.border.global"),
                        TitledBorder.LEADING,
                        TitledBorder.TOP,
                        null,
                        null));
        settingsPanel.add(globalSettingsPanel, panelConstraints);

        GridBagLayout settingPanelLayout = new GridBagLayout();
        globalSettingsPanel.setLayout(settingPanelLayout);

        GridBagConstraints gridBagConstraints = new GridBagConstraints();
        gridBagConstraints.anchor = GridBagConstraints.WEST;
        gridBagConstraints.fill = GridBagConstraints.NONE;
        gridBagConstraints.weightx = 1.0;
        gridBagConstraints.gridy = 0;
        gridBagConstraints.gridx = 0;

        SAMLConfiguration configuration = SAMLConfiguration.getInstance();
        chckbxEnablePassiveChanger =
                new JCheckBox(SamlI18n.getMessage("saml.settings.chkbox.passivechanger"));
        chckbxEnablePassiveChanger.setSelected(configuration.getAutoChangeEnabled());
        globalSettingsPanel.add(chckbxEnablePassiveChanger, gridBagConstraints);

        gridBagConstraints.gridy++;
        chckbxDeflateOnSend =
                new JCheckBox(SamlI18n.getMessage("saml.settings.chkbox.deflateonsend"));
        chckbxDeflateOnSend.setSelected(configuration.isDeflateOnSendEnabled());
        globalSettingsPanel.add(chckbxDeflateOnSend, gridBagConstraints);

        gridBagConstraints.gridy++;
        chckbxRemoveMessageSignatures =
                new JCheckBox(SamlI18n.getMessage("saml.settings.chkbox.removesign"));
        chckbxRemoveMessageSignatures.setSelected(configuration.getXSWEnabled());
        globalSettingsPanel.add(chckbxRemoveMessageSignatures, gridBagConstraints);

        gridBagConstraints.gridy++;
        chckbxValidateAttributeValue =
                new JCheckBox(SamlI18n.getMessage("saml.settings.chkbox.typevalidate"));
        chckbxValidateAttributeValue.setSelected(configuration.isValidationEnabled());
        globalSettingsPanel.add(chckbxValidateAttributeValue, gridBagConstraints);

        panelConstraints.gridy++;
        panelConstraints.anchor = GridBagConstraints.FIRST_LINE_START;
        JPanel attributePanel = new JPanel();
        attributePanel.setBorder(
                new TitledBorder(
                        null,
                        SamlI18n.getMessage("saml.settings.border.autochange"),
                        TitledBorder.LEADING,
                        TitledBorder.TOP,
                        null,
                        null));
        settingsPanel.add(attributePanel, panelConstraints);
        attributePanel.setLayout(new GridBagLayout());

        gridBagConstraints.gridy = 0;
        for (final Attribute attribute : configuration.getAutoChangeAttributes()) {
            gridBagConstraints.gridx = 0;

            final JLabel lblAttribute = new JLabel(attribute.getViewName());
            attributePanel.add(lblAttribute, gridBagConstraints);

            gridBagConstraints.gridx++;
            final JTextField txtValue = new JTextField();
            lblAttribute.setLabelFor(txtValue);
            txtValue.setText(attribute.getValue().toString());
            txtValue.setColumns(20);
            attributePanel.add(txtValue, gridBagConstraints);

            txtValue.addFocusListener(
                    new FocusListener() {
                        @Override
                        public void focusGained(FocusEvent e) {}

                        @Override
                        public void focusLost(FocusEvent e) {
                            attribute.setValue(txtValue.getText());
                            onDesiredAttributeValueChange(attribute);
                        }
                    });

            gridBagConstraints.gridx++;
            JButton btnRemoveAttribute =
                    new JButton(SamlI18n.getMessage("saml.settings.button.removeattrib"));
            btnRemoveAttribute.addActionListener(
                    new ActionListener() {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                            int response =
                                    JOptionPane.showConfirmDialog(
                                            SamlExtentionSettingsUI.this,
                                            SamlI18n.getMessage(
                                                    "saml.settings.messages.confirmremove"),
                                            SamlI18n.getMessage("saml.settings.messages.confirm"),
                                            JOptionPane.YES_NO_OPTION);
                            if (response == JOptionPane.YES_OPTION) {
                                onDeleteDesiredAttribute(attribute);
                            }
                        }
                    });
            attributePanel.add(btnRemoveAttribute, gridBagConstraints);
            gridBagConstraints.gridy++;
        }

        panelConstraints.gridy++;
        panelConstraints.weighty = 1.0;
        panelConstraints.anchor = GridBagConstraints.FIRST_LINE_START;
        JPanel allAttributePanel = new JPanel();
        allAttributePanel.setBorder(
                new TitledBorder(
                        null,
                        SamlI18n.getMessage("saml.settings.border.attributes"),
                        TitledBorder.LEADING,
                        TitledBorder.TOP,
                        null,
                        null));
        settingsPanel.add(allAttributePanel, panelConstraints);
        allAttributePanel.setLayout(new GridBagLayout());

        gridBagConstraints.gridy = 0;
        for (final Attribute attribute : SAMLConfiguration.getInstance().getAvailableAttributes()) {
            gridBagConstraints.gridx = 0;

            final JLabel lblAttribute = new JLabel(attribute.getViewName());
            allAttributePanel.add(lblAttribute, gridBagConstraints);

            gridBagConstraints.gridx++;
            JLabel lblAttributeType = new JLabel(attribute.getValueType().name());
            allAttributePanel.add(lblAttributeType, gridBagConstraints);

            gridBagConstraints.gridx++;
            JButton btnRemoveAttribute =
                    new JButton(SamlI18n.getMessage("saml.settings.button.removeattrib"));
            btnRemoveAttribute.addActionListener(
                    new ActionListener() {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                            int response =
                                    JOptionPane.showConfirmDialog(
                                            SamlExtentionSettingsUI.this,
                                            SamlI18n.getMessage(
                                                    "saml.settings.messages.confirmremove"),
                                            SamlI18n.getMessage("saml.settings.messages.confirm"),
                                            JOptionPane.YES_NO_OPTION);
                            if (response == JOptionPane.YES_OPTION) {
                                onAttributeDelete(attribute);
                            }
                        }
                    });
            allAttributePanel.add(btnRemoveAttribute, gridBagConstraints);
            gridBagConstraints.gridy++;
        }
    }

    private boolean saveChanges() {
        configuration.setAutochangeEnabled(chckbxEnablePassiveChanger.isSelected());
        configuration.setDeflateOnSendEnabled(chckbxDeflateOnSend.isSelected());
        configuration.setXSWEnabled(chckbxRemoveMessageSignatures.isSelected());
        configuration.setValidationEnabled(chckbxValidateAttributeValue.isSelected());
        return configuration.saveConfiguration();
    }

    private void resetChanges() {
        try {
            SAMLConfiguration.getInstance().initialize();
            initAttributes();
        } catch (SAMLException e1) {
            JOptionPane.showMessageDialog(
                    SamlExtentionSettingsUI.this,
                    SamlI18n.getMessage("saml.editor.msg.resetfailed"),
                    SamlI18n.getMessage("saml.settings.messages.failed"),
                    JOptionPane.ERROR_MESSAGE);
            log.error("Resetting settings failed");
        }
    }

    @Override
    public void onDesiredAttributeValueChange(Attribute attribute) {
        initAttributes();
    }

    @Override
    public void onAddDesiredAttribute(Attribute attribute) {
        configuration.getAutoChangeAttributes().add(attribute);
        initAttributes();
    }

    @Override
    public void onDeleteDesiredAttribute(Attribute attribute) {
        configuration.getAutoChangeAttributes().remove(attribute);
        initAttributes();
    }

    @Override
    public Set<Attribute> getDesiredAttributes() {
        return configuration.getAutoChangeAttributes();
    }

    @Override
    public void onAttributeAdd(Attribute a) {
        SAMLConfiguration.getInstance().onAttributeAdd(a);
        initAttributes();
    }

    @Override
    public void onAttributeDelete(Attribute a) {
        SAMLConfiguration.getInstance().onAttributeDelete(a);
        initAttributes();
    }
}
