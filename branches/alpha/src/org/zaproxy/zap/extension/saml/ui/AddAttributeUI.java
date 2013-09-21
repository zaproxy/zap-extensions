package org.zaproxy.zap.extension.saml.ui;

import org.zaproxy.zap.extension.saml.Attribute;
import org.zaproxy.zap.extension.saml.AttributeListener;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class AddAttributeUI extends JFrame {

    private JPanel contentPane;
    private JTextField textFieldAttributeName;
    private JTextField textFieldViewName;
    private JTextField textFieldXpath;
    private AttributeListener attributeListener;

    /**
     * Create the frame.
     */
    public AddAttributeUI(AttributeListener l) {
        this.attributeListener = l;
        setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        setBounds(100, 100, 400, 300);
        contentPane = new JPanel();
        contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
        contentPane.setLayout(new BorderLayout(0, 0));
        setContentPane(contentPane);

        JLabel lblAddNewAttribute = new JLabel("<html><h2>Add New Attribute</h2></html>");
        contentPane.add(lblAddNewAttribute, BorderLayout.NORTH);

        JPanel centerPanel = new JPanel();
        contentPane.add(centerPanel, BorderLayout.CENTER);
        centerPanel.setLayout(new GridLayout(0, 2, 10, 10));

        JLabel lblAttributeName = new JLabel("Attribute Name");
        centerPanel.add(lblAttributeName);

        textFieldAttributeName = new JTextField();
        centerPanel.add(textFieldAttributeName);
        textFieldAttributeName.setColumns(10);

        JLabel lblAttributeViewName = new JLabel("View Name (Max 30 Char.)");
        centerPanel.add(lblAttributeViewName);

        textFieldViewName = new JTextField();
        centerPanel.add(textFieldViewName);
        textFieldViewName.setColumns(10);

        JLabel lblXpath = new JLabel("XPath");
        centerPanel.add(lblXpath);

        textFieldXpath = new JTextField();
        centerPanel.add(textFieldXpath);
        textFieldXpath.setColumns(10);

        JLabel lblValueType = new JLabel("Value Type");
        centerPanel.add(lblValueType);

        final JComboBox<Attribute.SAMLAttributeValueType> comboBoxValueType = new JComboBox<>();
        centerPanel.add(comboBoxValueType);

        for (Attribute.SAMLAttributeValueType samlAttributeValueType : Attribute.SAMLAttributeValueType.values()) {
            comboBoxValueType.addItem(samlAttributeValueType);
        }

        JPanel bottomPanel = new JPanel();
        contentPane.add(bottomPanel, BorderLayout.SOUTH);

        JButton btnNewButton = new JButton("Save and Exit");
        btnNewButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                String error = "";
                if (textFieldAttributeName.getText().equals("")) {
                    error = "Attribute Name is empty\n";
                }
                if (textFieldViewName.getText().equals("")) {
                    error += "Attribute View Name is empty\n";
                }
                if (textFieldViewName.getText().length() > 30) {
                    error += "Attribute View Name should be less than 30 Characters\n";
                }
                if (textFieldXpath.getText().equals("")) {
                    error += "XPath is empty\n";
                }

                //validate xpath expression
                XPathFactory xFactory = XPathFactory.newInstance();
                XPath xpath = xFactory.newXPath();
                try {
                    XPathExpression expression = xpath.compile(textFieldXpath.getText());
                } catch (XPathExpressionException e1) {
                    error += "Invalid XPath";
                }

                if (!error.equals("")) {
                    //Something wrong with inputs
                    JOptionPane.showMessageDialog(AddAttributeUI.this, error, "Error with input values", JOptionPane.ERROR_MESSAGE);
                } else {
                    //valid input
                    Attribute attribute = new Attribute();
                    attribute.setName(textFieldAttributeName.getText());
                    attribute.setViewName(textFieldViewName.getText());
                    attribute.setxPath(textFieldXpath.getText());
                    attribute.setValueType((Attribute.SAMLAttributeValueType) comboBoxValueType.getSelectedItem());
                    attributeListener.onAttributeAdd(attribute);
                    close();
                }

            }
        });
        bottomPanel.add(btnNewButton);

        JButton btnCancel = new JButton("Cancel");
        btnCancel.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                int response = JOptionPane.showConfirmDialog(AddAttributeUI.this, "Are you sure?", "Confirm exit",
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
