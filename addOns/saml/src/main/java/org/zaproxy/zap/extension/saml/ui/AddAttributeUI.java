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
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.border.EmptyBorder;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import org.zaproxy.zap.extension.saml.Attribute;
import org.zaproxy.zap.extension.saml.AttributeListener;
import org.zaproxy.zap.extension.saml.SamlI18n;

public class AddAttributeUI extends JFrame {

    private static final long serialVersionUID = 1L;
    private JTextField textFieldAttributeName;
    private JTextField textFieldViewName;
    private JTextField textFieldXpath;
    private AttributeListener attributeListener;

    /** Create the frame. */
    public AddAttributeUI(AttributeListener l) {
        this.attributeListener = l;
        setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        setBounds(100, 100, 400, 250);
        JPanel contentPane = new JPanel();
        contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
        contentPane.setLayout(new BorderLayout());
        setContentPane(contentPane);

        JLabel lblAddNewAttribute = new JLabel(SamlI18n.getMessage("saml.addattrib.header"));
        contentPane.add(lblAddNewAttribute, BorderLayout.PAGE_START);

        JPanel centerPanel = new JPanel();
        contentPane.add(centerPanel, BorderLayout.CENTER);
        centerPanel.setLayout(new GridBagLayout());

        GridBagConstraints c = new GridBagConstraints();
        c.gridx = 0;
        c.gridy = 0;
        c.weightx = 0.5;
        c.fill = GridBagConstraints.HORIZONTAL;

        JLabel lblAttributeName = new JLabel(SamlI18n.getMessage("saml.addattrib.attribname"));
        centerPanel.add(lblAttributeName, c);

        c.gridx++;

        textFieldAttributeName = new JTextField();
        centerPanel.add(textFieldAttributeName, c);

        c.gridx = 0;
        c.gridy++;

        JLabel lblAttributeViewName =
                new JLabel(SamlI18n.getMessage("saml.addattrib.attribviewname"));
        centerPanel.add(lblAttributeViewName, c);

        c.gridx++;

        textFieldViewName = new JTextField();
        centerPanel.add(textFieldViewName, c);

        c.gridx = 0;
        c.gridy++;
        JLabel lblXpath = new JLabel(SamlI18n.getMessage("saml.addattrib.attribxpath"));
        centerPanel.add(lblXpath, c);

        c.gridx++;
        textFieldXpath = new JTextField();
        centerPanel.add(textFieldXpath, c);

        c.gridx = 0;
        c.gridy++;

        JLabel lblValueType = new JLabel(SamlI18n.getMessage("saml.addattrib.attribvaluetype"));
        centerPanel.add(lblValueType, c);

        c.gridx++;
        final JComboBox<Attribute.SAMLAttributeValueType> comboBoxValueType = new JComboBox<>();
        centerPanel.add(comboBoxValueType, c);

        for (Attribute.SAMLAttributeValueType samlAttributeValueType :
                Attribute.SAMLAttributeValueType.values()) {
            comboBoxValueType.addItem(samlAttributeValueType);
        }

        JPanel bottomPanel = new JPanel();
        contentPane.add(bottomPanel, BorderLayout.SOUTH);

        JButton btnNewButton = new JButton(SamlI18n.getMessage("saml.addattrib.button.saveexit"));
        btnNewButton.addActionListener(
                new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        String error = "";
                        if (textFieldAttributeName.getText().equals("")) {
                            error = SamlI18n.getMessage("saml.addattrib.error.noname") + "\n";
                        }
                        if (textFieldViewName.getText().equals("")) {
                            error += SamlI18n.getMessage("saml.addattrib.error.noviewname") + "\n";
                        }
                        if (textFieldViewName.getText().length() > 30) {
                            error +=
                                    SamlI18n.getMessage("saml.addattrib.error.longviewname") + "\n";
                        }
                        if (textFieldXpath.getText().equals("")) {
                            error += SamlI18n.getMessage("saml.addattrib.error.noxpath") + "\n";
                        }

                        // validate xpath expression
                        XPathFactory xFactory = XPathFactory.newInstance();
                        XPath xpath = xFactory.newXPath();
                        try {
                            xpath.compile(textFieldXpath.getText());
                        } catch (XPathExpressionException e1) {
                            error +=
                                    SamlI18n.getMessage("saml.addattrib.error.invalidxpath") + "\n";
                        }

                        if (!error.equals("")) {
                            // Something wrong with inputs
                            JOptionPane.showMessageDialog(
                                    AddAttributeUI.this,
                                    error,
                                    SamlI18n.getMessage("saml.addattrib.error.error"),
                                    JOptionPane.ERROR_MESSAGE);
                        } else {
                            // valid input
                            Attribute attribute = new Attribute();
                            attribute.setName(textFieldAttributeName.getText());
                            attribute.setViewName(textFieldViewName.getText());
                            attribute.setxPath(textFieldXpath.getText());
                            attribute.setValueType(
                                    (Attribute.SAMLAttributeValueType)
                                            comboBoxValueType.getSelectedItem());
                            attributeListener.onAttributeAdd(attribute);
                            close();
                        }
                    }
                });
        bottomPanel.add(btnNewButton);

        JButton btnCancel = new JButton(SamlI18n.getMessage("saml.addattrib.button.cancel"));
        btnCancel.addActionListener(
                new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        int response =
                                JOptionPane.showConfirmDialog(
                                        AddAttributeUI.this,
                                        SamlI18n.getMessage("saml.addattrib.msg.confirm"),
                                        SamlI18n.getMessage("saml.addattrib.msg.confirmexit"),
                                        JOptionPane.YES_NO_OPTION);
                        if (response == JOptionPane.YES_OPTION) {
                            close();
                        }
                    }
                });
        bottomPanel.add(btnCancel);
    }

    private void close() {
        setVisible(false);
        dispose();
    }
}
