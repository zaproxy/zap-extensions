package org.zaproxy.zap.extension.saml.ui;

import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.saml.*;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class AddAutoChangeAttributeUI extends JDialog {

    private static final long serialVersionUID = 1L;
    private JComboBox<Attribute> comboBoxAttribSelect;
    private JTextField txtAttribValues;

    /**
     * Create the dialog.
     */
    public AddAutoChangeAttributeUI(final PassiveAttributeChangeListener listener) {
        setTitle(SamlI18n.getMessage("saml.addchangeattrib.header"));
        setBounds(100, 100, 450, 150);
        getContentPane().setLayout(new BorderLayout());
        JPanel contentPanel = new JPanel();
        contentPanel.setBorder(new EmptyBorder(5, 5, 5, 5));
        getContentPane().add(contentPanel, BorderLayout.CENTER);
        contentPanel.setLayout(new GridBagLayout());

        GridBagConstraints c = new GridBagConstraints();
        c.fill = GridBagConstraints.HORIZONTAL;
        JLabel lblName = new JLabel(SamlI18n.getMessage("saml.addchangeattrib.attribname"));

        c.weightx = 0.5;
        c.gridx = 0;
        c.gridy = 0;
        c.insets = new Insets(10,0,0,0);

        contentPanel.add(lblName,c);

        comboBoxAttribSelect = new JComboBox<>();
        for (Attribute attribute : SAMLConfiguration.getInstance().getAvailableAttributes()) {
            if (!listener.getDesiredAttributes().contains(attribute)) {
                comboBoxAttribSelect.addItem(attribute);
            }
        }
        comboBoxAttribSelect.setMaximumRowCount(5);

        c.gridx++;
        contentPanel.add(comboBoxAttribSelect,c);

        c.gridy++;
        c.gridx = 0;
        JLabel lblValue = new JLabel(SamlI18n.getMessage("saml.addchangeattrib.attribvalue"));
        contentPanel.add(lblValue,c);

        c.gridx++;
        txtAttribValues = new JTextField();
        contentPanel.add(txtAttribValues, c);

        JPanel footerPanel = new JPanel();
        footerPanel.setLayout(new FlowLayout());
        getContentPane().add(footerPanel,BorderLayout.SOUTH);


        final JButton okButton = new JButton(SamlI18n.getMessage("saml.addchangeattrib.btn.ok"));
        okButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (comboBoxAttribSelect.getSelectedItem() == null) {
                    View.getSingleton().showWarningDialog(SamlI18n.getMessage("saml.addchangeattrib.msg.attribnotselected"));
                    return;
                }
                if (txtAttribValues.getText().equals("")) {
                    JOptionPane.showMessageDialog(AddAutoChangeAttributeUI.this, SamlI18n.getMessage("saml.addchangeattrib.msg.novalue"), SamlI18n.getMessage("saml.addchangeattrib.msg.valueerror"), JOptionPane.ERROR_MESSAGE);
                    return;
                }
                Attribute attribute = ((Attribute) comboBoxAttribSelect.getSelectedItem()).createCopy();
                attribute.setValue(txtAttribValues.getText());
                listener.onAddDesiredAttribute(attribute);
                AddAutoChangeAttributeUI.this.setVisible(false);
            }
        });
        footerPanel.add(okButton);
        getRootPane().setDefaultButton(okButton);

        JButton cancelButton = new JButton(SamlI18n.getMessage("saml.addchangeattrib.btn.cancel"));
        cancelButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                AddAutoChangeAttributeUI.this.setVisible(false);
            }
        });
        footerPanel.add(cancelButton);

    }

    /**
     * Get the combo box object to update its contents
     *
     * @return
     */
    public JComboBox<Attribute> getComboBoxAttribSelect() {
        return comboBoxAttribSelect;
    }

    /**
     * Get the value textfield to update its content
     *
     * @return
     */
    public JTextField getTxtAttribValues() {
        return txtAttribValues;
    }


}
