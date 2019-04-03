package org.zaproxy.zap.extension.vulncheck;
import java.awt.BorderLayout;
import java.awt.EventQueue;

import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;
import javax.swing.JLayeredPane;
import javax.swing.JCheckBox;
import javax.swing.JScrollPane;
import javax.swing.JTextField;
import javax.swing.JButton;
import javax.swing.JLabel;

import org.json.simple.parser.ParseException;

import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import java.io.IOException;
import java.util.ArrayList;

import javax.swing.JTextPane;


public class VulnCheckerFrame extends JFrame {

	private static final long serialVersionUID = 1L;
	private JPanel contentPane;
	private JTextField textField;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					VulnCheckerFrame frame = new VulnCheckerFrame();
					frame.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	/**
	 * Create the frame.
	 */
	public VulnCheckerFrame() {
		setDefaultCloseOperation(JFrame.HIDE_ON_CLOSE);
		setBounds(100, 100, 675, 300);
		contentPane = new JPanel();
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
		contentPane.setLayout(new BorderLayout(0, 0));
		setContentPane(contentPane);
		
		JLayeredPane layeredPane = new JLayeredPane();
		contentPane.add(layeredPane, BorderLayout.CENTER);
		
		JLayeredPane layeredPane_1 = new JLayeredPane();
		layeredPane_1.setBounds(0, 0, 649, 251);
		layeredPane.add(layeredPane_1);
		
		
		final JCheckBox chckbxNewCheckBox = new JCheckBox("Shodan");
		chckbxNewCheckBox.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				
			}
		});
		chckbxNewCheckBox.setBounds(29, 74, 97, 23);
		layeredPane_1.add(chckbxNewCheckBox);
		
		final JCheckBox chckbxNewCheckBox_1 = new JCheckBox("CVE");
		chckbxNewCheckBox_1.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				
			}
		});
		chckbxNewCheckBox_1.setBounds(29, 100, 97, 23);
		layeredPane_1.add(chckbxNewCheckBox_1);
		
		final JCheckBox chckbxNewCheckBox_2 = new JCheckBox("Packetstorm");
		chckbxNewCheckBox_2.setBounds(29, 126, 97, 23);
		layeredPane_1.add(chckbxNewCheckBox_2);
		
		final JCheckBox chckbxSecurititeam = new JCheckBox("Securititeam");
		chckbxSecurititeam.setBounds(29, 152, 97, 23);
		layeredPane_1.add(chckbxSecurititeam);
		
		textField = new JTextField();
		textField.setBounds(29, 36, 163, 31);
		layeredPane_1.add(textField);
		textField.setColumns(10);
		final JTextPane textPane = new JTextPane();
		JButton btnNewButton = new JButton("Search");
		btnNewButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if (chckbxNewCheckBox.isSelected()){
					chckbxNewCheckBox_1.setSelected(false);
					chckbxNewCheckBox_2.setSelected(false);
					chckbxSecurititeam.setSelected(false);
					try {
						textPane.setText(ShodanAPI.host(textField.getText()).toString());
					} catch (IOException | ParseException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}
				}
				if (chckbxNewCheckBox_1.isSelected()){
					chckbxNewCheckBox.setSelected(false);
					chckbxNewCheckBox_2.setSelected(false);
					chckbxSecurititeam.setSelected(false);
					try {
						textPane.setText((VulnChecker.getCve(textField.getText(),"1.5")).toString());
					} catch (Exception e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}
				}
				if (chckbxNewCheckBox_2.isSelected()){
					chckbxNewCheckBox.setSelected(false);
					chckbxNewCheckBox_1.setSelected(false);
					chckbxSecurititeam.setSelected(false);
					try {
					
						ArrayList<String> results = VulnChecker.fromPacketStorm(textField.getText(),"1.5");
						for(int i = 0; i<results.size();i++){
							textPane.setText(textPane.getText().concat("http://packetstormsecurity.org/"+results.get(i)+"\n"));
						}
					} catch (Exception e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}
				}
				if (chckbxSecurititeam.isSelected()){
					chckbxNewCheckBox.setSelected(false);
					chckbxNewCheckBox_1.setSelected(false);
					chckbxNewCheckBox_2.setSelected(false);
					try {
					
						ArrayList<String> results = VulnChecker.fromSecuritiTeam(textField.getText(),"1.5");
						for(int i = 0; i<results.size();i++){
							textPane.setText(textPane.getText().concat(results.get(i)));
						}
					} catch (Exception e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}
				}
				
			}
		});
		btnNewButton.setBounds(64, 197, 102, 23);
		layeredPane_1.add(btnNewButton);
		
		JLabel lblApplicationName = new JLabel("Application name:");
		lblApplicationName.setBounds(29, 21, 149, 14);
		layeredPane_1.add(lblApplicationName);
		
		JScrollPane scrollPane = new JScrollPane();
		scrollPane.setBounds(234, 21, 365, 199);
		layeredPane_1.add(scrollPane);
		
		scrollPane.setViewportView(textPane);
	}
}
