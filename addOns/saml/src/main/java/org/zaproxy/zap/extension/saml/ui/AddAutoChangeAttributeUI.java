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
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.border.EmptyBorder;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.saml.Attribute;
import org.zaproxy.zap.extension.saml.PassiveAttributeChangeListener;
import org.zaproxy.zap.extension.saml.SAMLConfiguration;
import org.zaproxy.zap.extension.saml.SamlI18n;

public class AddAutoChangeAttributeUI extends JDialog {

    private static final long serialVersionUID = 1L;
    private JComboBox<Attribute> comboBoxAttribSelect;
    private JTextField txtAttribValues;

    /** Create the dialog. */
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
        c.insets = new Insets(10, 0, 0, 0);

        contentPanel.add(lblName, c);

        comboBoxAttribSelect = new JComboBox<>();
        for (Attribute attribute : SAMLConfiguration.getInstance().getAvailableAttributes()) {
            if (!listener.getDesiredAttributes().contains(attribute)) {
                comboBoxAttribSelect.addItem(attribute);
            }
        }
        comboBoxAttribSelect.setMaximumRowCount(5);

        c.gridx++;
        contentPanel.add(comboBoxAttribSelect, c);

        c.gridy++;
        c.gridx = 0;
        JLabel lblValue = new JLabel(SamlI18n.getMessage("saml.addchangeattrib.attribvalue"));
        contentPanel.add(lblValue, c);

        c.gridx++;
        txtAttribValues = new JTextField();
        contentPanel.add(txtAttribValues, c);

        JPanel footerPanel = new JPanel();
        footerPanel.setLayout(new FlowLayout());
        getContentPane().add(footerPanel, BorderLayout.SOUTH);

        final JButton okButton = new JButton(SamlI18n.getMessage("saml.addchangeattrib.btn.ok"));
        okButton.addActionListener(
                new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        if (comboBoxAttribSelect.getSelectedItem() == null) {
                            View.getSingleton()
                                    .showWarningDialog(
                                            SamlI18n.getMessage(
                                                    "saml.addchangeattrib.msg.attribnotselected"));
                            return;
                        }
                        if (txtAttribValues.getText().equals("")) {
                            JOptionPane.showMessageDialog(
                                    AddAutoChangeAttributeUI.this,
                                    SamlI18n.getMessage("saml.addchangeattrib.msg.novalue"),
                                    SamlI18n.getMessage("saml.addchangeattrib.msg.valueerror"),
                                    JOptionPane.ERROR_MESSAGE);
                            return;
                        }
                        Attribute attribute =
                                ((Attribute) comboBoxAttribSelect.getSelectedItem()).createCopy();
                        attribute.setValue(txtAttribValues.getText());
                        listener.onAddDesiredAttribute(attribute);
                        AddAutoChangeAttributeUI.this.setVisible(false);
                    }
                });
        footerPanel.add(okButton);
        getRootPane().setDefaultButton(okButton);

        JButton cancelButton = new JButton(SamlI18n.getMessage("saml.addchangeattrib.btn.cancel"));
        cancelButton.addActionListener(
                new ActionListener() {
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
