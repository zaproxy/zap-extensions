package org.zaproxy.zap.extension.saml.ui;

import org.zaproxy.zap.extension.saml.Attribute;
import org.zaproxy.zap.extension.saml.AttributeChangeListener;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;
import javax.swing.JScrollPane;
import javax.swing.JLabel;
import javax.swing.JTextArea;

public class ChangeAttribValueDialog extends JDialog {

    private JTextArea textAreaValues;

	/**
	 * Create the dialog.
	 */
	public ChangeAttribValueDialog(final AttributeChangeListener listener, final Attribute attribute) {
		setTitle("Add/Edit values for "+attribute.getViewName());
		setBounds(100, 100, 450, 300);
		getContentPane().setLayout(new BorderLayout());
        JScrollPane contentPanel = new JScrollPane();
        contentPanel.setBorder(new EmptyBorder(5, 5, 5, 5));
		getContentPane().add(contentPanel, BorderLayout.CENTER);
		contentPanel.setLayout(new BorderLayout(0, 0));
		{
			JLabel lblHeader = new JLabel("One value per line");
			contentPanel.setColumnHeaderView(lblHeader);
		}
		{
			textAreaValues = new JTextArea();
            textAreaValues.setText(attribute.getValue().toString());
            contentPanel.setViewportView(textAreaValues);
		}
		{
			JPanel buttonPane = new JPanel();
			buttonPane.setLayout(new FlowLayout(FlowLayout.RIGHT));
			getContentPane().add(buttonPane, BorderLayout.SOUTH);
			{
				JButton okButton = new JButton("OK");
				okButton.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        String value = textAreaValues.getText();
                        attribute.setValue(value);
                        listener.onDesiredAttributeValueChange(attribute);
                        ChangeAttribValueDialog.this.setVisible(false);
                    }
                });
				buttonPane.add(okButton);
				getRootPane().setDefaultButton(okButton);
			}
			{
				JButton cancelButton = new JButton("Cancel");
				cancelButton.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        ChangeAttribValueDialog.this.setVisible(false);
                    }
                });
				buttonPane.add(cancelButton);
			}
		}
	}

}
