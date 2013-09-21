package org.zaproxy.zap.extension.saml.ui;

import org.zaproxy.zap.extension.saml.*;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.LinkedHashSet;
import java.util.Set;

public class SamlExtentionSettingsUI extends JFrame implements PassiveAttributeChangeListener, AttributeListener {

    private JScrollPane settingsScrollPane;
    private Set<Attribute> attributeSet;
    JCheckBox chckbxEnablePassiveChanger;
    JCheckBox chckbxRemoveMessageSignatures;
    JCheckBox chckbxValidateAttributeValue;

    /**
     * Create the frame.
     */
    public SamlExtentionSettingsUI(final SAMLProxyListener listener) {
        setTitle("SAML Settings");
        setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        setSize(800, 700);
        setLocationRelativeTo(null);
        JPanel contentPane = new JPanel();
        contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
        contentPane.setLayout(new BorderLayout(0, 0));
        setContentPane(contentPane);

        JLabel lblHeaderlabel = new JLabel("<html><h2>SAML Settings</h2></html>");
        contentPane.add(lblHeaderlabel, BorderLayout.NORTH);

        settingsScrollPane = new JScrollPane();
        contentPane.add(settingsScrollPane, BorderLayout.CENTER);

        JPanel footerPanel = new JPanel();
        contentPane.add(footerPanel, BorderLayout.SOUTH);
        footerPanel.setLayout(new FlowLayout(FlowLayout.LEFT, 5, 5));

        JButton btnAddAutoChange = new JButton("Add Auto Change attributes");
        btnAddAutoChange.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                AddAutoChangeAttributeUI dialog = new AddAutoChangeAttributeUI(SamlExtentionSettingsUI.this);
                dialog.setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);
                dialog.setVisible(true);
            }
        });
        footerPanel.add(btnAddAutoChange);

        JButton btnAdd = new JButton("Add SAML Attributes");
        btnAdd.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                AddAttributeUI addAttributeUI = new AddAttributeUI(SamlExtentionSettingsUI.this);
                addAttributeUI.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
                addAttributeUI.setVisible(true);
            }
        });
        footerPanel.add(btnAdd);

        JButton btnSaveChanges = new JButton("Save Changes");
        btnSaveChanges.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                SAMLConfiguration samlConfiguration = SAMLConfiguration.getInstance();
                samlConfiguration.getAutoChangeAttributes().clear();
                samlConfiguration.getAutoChangeAttributes().addAll(attributeSet);
                listener.loadAutoChangeAttributes();
                samlConfiguration.setAutochangeEnabled(chckbxEnablePassiveChanger.isSelected());
                samlConfiguration.setXSWEnabled(chckbxRemoveMessageSignatures.isSelected());
                samlConfiguration.setValidationEnabled(chckbxValidateAttributeValue.isSelected());
                boolean success = samlConfiguration.saveConfiguration();
                if (success) {
                    JOptionPane.showMessageDialog(SamlExtentionSettingsUI.this, "Changes saved", "Success",
                            JOptionPane.INFORMATION_MESSAGE);
                } else {
                    JOptionPane.showMessageDialog(SamlExtentionSettingsUI.this, "Could not save changes. Please retry",
                            "Failed", JOptionPane.ERROR_MESSAGE);
                }
            }
        });
        footerPanel.add(btnSaveChanges);

        JButton btnResetChanges = new JButton("Reset changes");
        btnResetChanges.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                loadAutoChangeAttributes();
                initAttributes();
            }
        });
        footerPanel.add(btnResetChanges);

        JButton btnExit = new JButton("Exit");
        btnExit.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                SamlExtentionSettingsUI.this.setVisible(false);
            }
        });
        footerPanel.add(btnExit);
        loadAutoChangeAttributes();
        initAttributes();
    }

    /**
     * Load the auto change attributes
     */
    private void loadAutoChangeAttributes() {
        attributeSet = new LinkedHashSet<>();
        for (Attribute autoChangeAttribute : SAMLConfiguration.getInstance().getAutoChangeAttributes()) {
            Attribute clonedAttribute = autoChangeAttribute.createCopy();
            clonedAttribute.setValue(autoChangeAttribute.getValue());
            attributeSet.add(clonedAttribute);
        }
    }

    /**
     * Initialize UI with the attributes
     */
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
        globalSettingsPanel.setBorder(new TitledBorder(null, "Global Settings", TitledBorder.LEADING, TitledBorder.TOP, null, null));
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
        chckbxEnablePassiveChanger = new JCheckBox("Enable Passive changer");
        chckbxEnablePassiveChanger.setSelected(configuration.getAutoChangeEnabled());
        globalSettingsPanel.add(chckbxEnablePassiveChanger, gridBagConstraints);

        gridBagConstraints.gridy++;
        chckbxRemoveMessageSignatures = new JCheckBox("Remove message signatures");
        chckbxRemoveMessageSignatures.setSelected(configuration.getXSWEnabled());
        globalSettingsPanel.add(chckbxRemoveMessageSignatures, gridBagConstraints);

        gridBagConstraints.gridy++;
        chckbxValidateAttributeValue = new JCheckBox("Validate attribute value types");
        chckbxValidateAttributeValue.setSelected(configuration.isValidationEnabled());
        globalSettingsPanel.add(chckbxValidateAttributeValue, gridBagConstraints);

        panelConstraints.gridy++;
        panelConstraints.anchor = GridBagConstraints.FIRST_LINE_START;
        JPanel attributePanel = new JPanel();
        attributePanel.setBorder(new TitledBorder(null, "Auto Change Attributes and Values", TitledBorder.LEADING, TitledBorder.TOP, null, null));
        settingsPanel.add(attributePanel, panelConstraints);
        attributePanel.setLayout(new GridBagLayout());

        gridBagConstraints.gridy = 0;
        for (final Attribute attribute : attributeSet) {
            gridBagConstraints.gridx = 0;

            final JLabel lblAttribute = new JLabel(attribute.getViewName());
            attributePanel.add(lblAttribute, gridBagConstraints);

            gridBagConstraints.gridx++;
            JTextField txtValue = new JTextField();
            lblAttribute.setLabelFor(txtValue);
            txtValue.setText(attribute.getValue().toString());
            txtValue.setColumns(20);
            txtValue.setEnabled(false);
            attributePanel.add(txtValue, gridBagConstraints);

            gridBagConstraints.gridx++;
            JButton btnAddeditValues = new JButton("Add/Edit Values");
            btnAddeditValues.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    AddAutoChangeAttributeUI editDialog = new AddAutoChangeAttributeUI(SamlExtentionSettingsUI.this);
                    editDialog.getComboBoxAttribSelect().removeAllItems();
                    editDialog.getComboBoxAttribSelect().addItem(attribute);
                    editDialog.getTxtAttribValues().setText(attribute.getValue().toString().replaceAll(",", "\n"));
                    editDialog.setVisible(true);
                }
            });
            attributePanel.add(btnAddeditValues, gridBagConstraints);

            gridBagConstraints.gridx++;
            JButton btnRemoveAttribute = new JButton("Remove Attribute");
            btnRemoveAttribute.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    int response = JOptionPane.showConfirmDialog(SamlExtentionSettingsUI.this,
                            "Are you sure to remove the attribute", "Confirm", JOptionPane.YES_NO_OPTION);
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
        allAttributePanel.setBorder(new TitledBorder(null, "Configured Attributes", TitledBorder.LEADING,
                TitledBorder.TOP, null, null));
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
            JButton btnRemoveAttribute = new JButton("Remove Attribute");
            btnRemoveAttribute.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    int response = JOptionPane.showConfirmDialog(SamlExtentionSettingsUI.this,
                            "Are you sure to remove the attribute", "Confirm", JOptionPane.YES_NO_OPTION);
                    if (response == JOptionPane.YES_OPTION) {
                        onAttributeDelete(attribute);
                    }
                }
            });
            allAttributePanel.add(btnRemoveAttribute, gridBagConstraints);
            gridBagConstraints.gridy++;
        }
    }

    @Override
    public void onDesiredAttributeValueChange(Attribute attribute) {
        onAddDesiredAttribute(attribute);
        initAttributes();
    }

    @Override
    public void onAddDesiredAttribute(Attribute attribute) {
        attributeSet.add(attribute);
        initAttributes();
    }

    @Override
    public void onDeleteDesiredAttribute(Attribute attribute) {
        attributeSet.remove(attribute);
        initAttributes();
    }

    @Override
    public Set<Attribute> getDesiredAttributes() {
        return attributeSet;
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
