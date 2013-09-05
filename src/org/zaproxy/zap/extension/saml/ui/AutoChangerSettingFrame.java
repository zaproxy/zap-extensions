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

public class AutoChangerSettingFrame extends JFrame implements DesiredAttributeChangeListener {

    private JScrollPane attributeScrollPane;
    private Set<Attribute> attributeSet;

	/**
	 * Create the frame.
	 */
	public AutoChangerSettingFrame(final SAMLProxyListener listener) {
		setTitle("SAML Automatic Request Changer Settings");
		setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
		setSize(800, 700);
		setLocationRelativeTo(null);
        JPanel contentPane = new JPanel();
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
		contentPane.setLayout(new BorderLayout(0, 0));
		setContentPane(contentPane);

		JLabel lblHeaderlabel = new JLabel("<html><h2>SAML Settings</h2></html>");
		contentPane.add(lblHeaderlabel, BorderLayout.NORTH);
		
		attributeScrollPane = new JScrollPane();
        contentPane.add(attributeScrollPane, BorderLayout.CENTER);
		


		JPanel footerPanel = new JPanel();
		contentPane.add(footerPanel, BorderLayout.SOUTH);
		footerPanel.setLayout(new FlowLayout(FlowLayout.LEFT, 5, 5));
		
		JButton btnAdd = new JButton("Add more attributes");
        btnAdd.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                AddNewAttributeDialog dialog = new AddNewAttributeDialog(AutoChangerSettingFrame.this);
                dialog.setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);
                dialog.setVisible(true);
            }
        });
		footerPanel.add(btnAdd);
		
		JButton btnSaveChanges = new JButton("Save Changes");
        btnSaveChanges.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                SAMLConfiguration.getConfigurations().getAutoChangeAttributes().clear();
                SAMLConfiguration.getConfigurations().getAutoChangeAttributes().addAll(attributeSet);
                listener.loadAutoChangeAttributes();
                boolean success = SAMLConfiguration.getConfigurations().saveConfiguration();
                if(success){
                    JOptionPane.showMessageDialog(AutoChangerSettingFrame.this,"Changes saved","Sucess",
                            JOptionPane.INFORMATION_MESSAGE);
                } else{
                    JOptionPane.showMessageDialog(AutoChangerSettingFrame.this,"Changes saved","Sucess",
                            JOptionPane.ERROR_MESSAGE);
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
                AutoChangerSettingFrame.this.setVisible(false);
            }
        });
		footerPanel.add(btnExit);
        loadAutoChangeAttributes();
        initAttributes();
	}

    private void loadAutoChangeAttributes(){
        attributeSet = new LinkedHashSet<>();
        try {
            for (Attribute autoChangeAttribute : SAMLConfiguration.getConfigurations().getAutoChangeAttributes()) {
                Attribute clonedAttribute = (Attribute)autoChangeAttribute.clone();
                clonedAttribute.setValue(autoChangeAttribute.getValue());
                attributeSet.add(clonedAttribute);
            }
        } catch (CloneNotSupportedException ignored) {
        }
    }

    private void initAttributes(){
        JPanel attributePanel = new JPanel();
        attributeScrollPane.setViewportView(attributePanel);
        attributePanel.setLayout(new GridLayout(Math.max(attributeSet.size()+1,15), 1, 5, 0));
        attributePanel.setBorder(new TitledBorder("SAML Attributes to be changed automatically"));
        JPanel panel = new JPanel();
        attributePanel.add(panel);
        panel.setLayout(new FlowLayout(FlowLayout.LEFT, 5, 5));
        JLabel lblHeader = new JLabel("<html><p>Following attributes will be changed to the given values " +
                "automatically. Add/Edit the attributes and values below </p></html>");
        panel.add(lblHeader);
        for (final Attribute attribute : attributeSet) {
            panel = new JPanel();
            attributePanel.add(panel);
            panel.setLayout(new FlowLayout(FlowLayout.LEFT, 5, 5));

            final JLabel lblAttribute = new JLabel(attribute.getViewName());
            Dimension size = lblAttribute.getPreferredSize();
            size.width = 200;
            lblAttribute.setMinimumSize(size);
            lblAttribute.setPreferredSize(size);
            panel.add(lblAttribute);

            JTextField txtValue = new JTextField();
            lblAttribute.setLabelFor(txtValue);
            txtValue.setText(attribute.getValue().toString());
            panel.add(txtValue);
            txtValue.setColumns(20);

            JButton btnAddeditValues = new JButton("Add/Edit Values");
            btnAddeditValues.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    AddNewAttributeDialog editDialog = new AddNewAttributeDialog(AutoChangerSettingFrame.this);
                    editDialog.getComboBoxAttribSelect().removeAllItems();
                    editDialog.getComboBoxAttribSelect().addItem(attribute);
                    editDialog.getTxtAttribValues().setText(attribute.getValue().toString().replaceAll(",", "\n"));
                    editDialog.setVisible(true);
                }
            });
            panel.add(btnAddeditValues);

            JButton btnRemoveAttribute = new JButton("Remove Attribute");
            btnRemoveAttribute.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    int response = JOptionPane.showConfirmDialog(AutoChangerSettingFrame.this,
                            "Are you sure to remove the attribute","Confirm",JOptionPane.YES_NO_OPTION);
                    if(response == JOptionPane.YES_OPTION){
                        onDeleteDesiredAttribute(attribute);
                    }
                }
            });
            panel.add(btnRemoveAttribute);
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
}
