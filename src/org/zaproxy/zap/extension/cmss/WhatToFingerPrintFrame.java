package org.zaproxy.zap.extension.cmss;
import java.awt.BorderLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFrame;
import javax.swing.JLayeredPane;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;

public class WhatToFingerPrintFrame extends JFrame implements ActionListener {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private JPanel contentPane;
	// we save in this list all checkBoses then use them to get web apps category names and then category numbers
	private ArrayList<javax.swing.JCheckBox> checkBoxesList = new ArrayList<javax.swing.JCheckBox>();
	
	ArrayList<String> WhatToFingerprint = new ArrayList<String>();

	/**
	 * Create the frame.
	 */
	public WhatToFingerPrintFrame() {
		setDefaultCloseOperation(JFrame.HIDE_ON_CLOSE);
		setBounds(100, 100, 768, 300);
		setResizable(false);
		contentPane = new JPanel();
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
		contentPane.setLayout(new BorderLayout(0, 0));
		setContentPane(contentPane);
		
		JLayeredPane layeredPane = new JLayeredPane();
		contentPane.add(layeredPane, BorderLayout.CENTER);
		
		JCheckBox chckbxDatabasemanagers = new JCheckBox("database-managers");
		chckbxDatabasemanagers.setBounds(18, 7, 122, 23);
		layeredPane.add(chckbxDatabasemanagers);
		
		JCheckBox chckbxDocumentationtools = new JCheckBox("documentation-tools");
		chckbxDocumentationtools.setBounds(566, 7, 137, 23);
		layeredPane.add(chckbxDocumentationtools);
		
		JCheckBox chckbxNewCheckBox = new JCheckBox("widgets");
		chckbxNewCheckBox.setBounds(18, 56, 116, 23);
		layeredPane.add(chckbxNewCheckBox);
		
		JCheckBox chckbxWebshops = new JCheckBox("web-shops");
		chckbxWebshops.setBounds(18, 82, 116, 23);
		layeredPane.add(chckbxWebshops);
		
		JCheckBox chckbxNewCheckBox_1 = new JCheckBox("photo-galleries");
		chckbxNewCheckBox_1.setBounds(18, 107, 116, 23);
		layeredPane.add(chckbxNewCheckBox_1);
		
		JCheckBox chckbxNewCheckBox_2 = new JCheckBox("wikis");
		chckbxNewCheckBox_2.setBounds(18, 133, 116, 23);
		layeredPane.add(chckbxNewCheckBox_2);
		
		JCheckBox chckbxNewCheckBox_3 = new JCheckBox("hosting-panels");
		chckbxNewCheckBox_3.setBounds(18, 159, 116, 23);
		layeredPane.add(chckbxNewCheckBox_3);
		
		JCheckBox chckbxNewCheckBox_4 = new JCheckBox("analytics");
		chckbxNewCheckBox_4.setBounds(18, 185, 116, 23);
		layeredPane.add(chckbxNewCheckBox_4);
		
		JCheckBox chckbxNewCheckBox_5 = new JCheckBox("blogs");
		chckbxNewCheckBox_5.setBounds(142, 7, 116, 23);
		layeredPane.add(chckbxNewCheckBox_5);
		
		JCheckBox chckbxNewCheckBox_6 = new JCheckBox("issue-trackers");
		chckbxNewCheckBox_6.setBounds(142, 30, 116, 23);
		layeredPane.add(chckbxNewCheckBox_6);
		
		JCheckBox chckbxNewCheckBox_7 = new JCheckBox("video-players");
		chckbxNewCheckBox_7.setBounds(142, 56, 116, 23);
		layeredPane.add(chckbxNewCheckBox_7);
		
		JCheckBox chckbxNewCheckBox_8 = new JCheckBox("comment-systems");
		chckbxNewCheckBox_8.setBounds(142, 82, 116, 23);
		layeredPane.add(chckbxNewCheckBox_8);
		
		JCheckBox chckbxNewCheckBox_9 = new JCheckBox("captchas");
		chckbxNewCheckBox_9.setBounds(142, 107, 116, 23);
		layeredPane.add(chckbxNewCheckBox_9);
		
		JCheckBox chckbxNewCheckBox_10 = new JCheckBox("font-scripts");
		chckbxNewCheckBox_10.setBounds(142, 133, 116, 23);
		layeredPane.add(chckbxNewCheckBox_10);
		
		JCheckBox chckbxNewCheckBox_11 = new JCheckBox("miscellaneous");
		chckbxNewCheckBox_11.setBounds(142, 159, 116, 23);
		layeredPane.add(chckbxNewCheckBox_11);
		
		JCheckBox chckbxNewCheckBox_12 = new JCheckBox("editors");
		chckbxNewCheckBox_12.setBounds(142, 185, 116, 23);
		layeredPane.add(chckbxNewCheckBox_12);
		
		JCheckBox chckbxNewCheckBox_13 = new JCheckBox("lms");
		chckbxNewCheckBox_13.setBounds(276, 7, 114, 23);
		layeredPane.add(chckbxNewCheckBox_13);
		
		JCheckBox chckbxNewCheckBox_14 = new JCheckBox("cache-tools");
		chckbxNewCheckBox_14.setBounds(276, 30, 114, 23);
		layeredPane.add(chckbxNewCheckBox_14);
		
		JCheckBox chckbxNewCheckBox_15 = new JCheckBox("rich-text-editors");
		chckbxNewCheckBox_15.setBounds(276, 56, 114, 23);
		layeredPane.add(chckbxNewCheckBox_15);
		
		JCheckBox chckbxNewCheckBox_16 = new JCheckBox("javascript-graphics");
		chckbxNewCheckBox_16.setBounds(276, 82, 122, 23);
		layeredPane.add(chckbxNewCheckBox_16);
		
		JCheckBox chckbxNewCheckBox_17 = new JCheckBox("mobile-frameworks");
		chckbxNewCheckBox_17.setBounds(276, 107, 122, 23);
		layeredPane.add(chckbxNewCheckBox_17);
		
		JCheckBox chckbxNewCheckBox_18 = new JCheckBox("programming-languages");
		chckbxNewCheckBox_18.setBounds(427, 185, 137, 23);
		layeredPane.add(chckbxNewCheckBox_18);
		
		JCheckBox chckbxNewCheckBox_19 = new JCheckBox("operating-systems");
		chckbxNewCheckBox_19.setBounds(276, 159, 114, 23);
		layeredPane.add(chckbxNewCheckBox_19);
		
		JCheckBox chckbxNewCheckBox_20 = new JCheckBox("search-engines");
		chckbxNewCheckBox_20.setBounds(276, 185, 114, 23);
		layeredPane.add(chckbxNewCheckBox_20);
		
		JCheckBox chckbxNewCheckBox_21 = new JCheckBox("cdn");
		chckbxNewCheckBox_21.setBounds(427, 7, 137, 23);
		layeredPane.add(chckbxNewCheckBox_21);
		
		JCheckBox chckbxNewCheckBox_22 = new JCheckBox("marketing-automation");
		chckbxNewCheckBox_22.setBounds(427, 30, 137, 23);
		layeredPane.add(chckbxNewCheckBox_22);
		
		JCheckBox chckbxNewCheckBox_23 = new JCheckBox("web-server-extensions");
		chckbxNewCheckBox_23.setBounds(427, 56, 137, 23);
		layeredPane.add(chckbxNewCheckBox_23);
		
		JCheckBox chckbxNewCheckBox_24 = new JCheckBox("maps");
		chckbxNewCheckBox_24.setBounds(427, 82, 137, 23);
		layeredPane.add(chckbxNewCheckBox_24);
		
		JCheckBox chckbxNewCheckBox_25 = new JCheckBox("advertising-networks");
		chckbxNewCheckBox_25.setBounds(427, 107, 137, 23);
		layeredPane.add(chckbxNewCheckBox_25);
		
		JCheckBox chckbxNewCheckBox_26 = new JCheckBox("network-devices");
		chckbxNewCheckBox_26.setBounds(427, 133, 137, 23);
		layeredPane.add(chckbxNewCheckBox_26);
		
		JCheckBox chckbxNewCheckBox_27 = new JCheckBox("media-servers");
		chckbxNewCheckBox_27.setBounds(427, 159, 137, 23);
		layeredPane.add(chckbxNewCheckBox_27);
		
		JCheckBox chckbxNewCheckBox_28 = new JCheckBox("webcams");
		chckbxNewCheckBox_28.setBounds(276, 133, 97, 23);
		layeredPane.add(chckbxNewCheckBox_28);
		
		JCheckBox chckbxNewCheckBox_29 = new JCheckBox("printers");
		chckbxNewCheckBox_29.setBounds(18, 30, 116, 23);
		layeredPane.add(chckbxNewCheckBox_29);
		
		
		
		JButton btnOk = new JButton("OK");
		btnOk.addActionListener(this);
		btnOk.setBounds(615, 217, 97, 23);
		layeredPane.add(btnOk);
		
		checkBoxesList.add(chckbxNewCheckBox_1);
		checkBoxesList.add(chckbxNewCheckBox_2);
		checkBoxesList.add(chckbxNewCheckBox_3);
		checkBoxesList.add(chckbxNewCheckBox_4);
		checkBoxesList.add(chckbxNewCheckBox_5);
		checkBoxesList.add(chckbxNewCheckBox_6);
		checkBoxesList.add(chckbxNewCheckBox_7);
		checkBoxesList.add(chckbxNewCheckBox_8);
		checkBoxesList.add(chckbxNewCheckBox_9);
		checkBoxesList.add(chckbxNewCheckBox_10);
		checkBoxesList.add(chckbxNewCheckBox_11);
		checkBoxesList.add(chckbxNewCheckBox_12);
		checkBoxesList.add(chckbxNewCheckBox_13);
		checkBoxesList.add(chckbxNewCheckBox_14);
		checkBoxesList.add(chckbxNewCheckBox_15);
		checkBoxesList.add(chckbxNewCheckBox_16);
		checkBoxesList.add(chckbxNewCheckBox_17);
		checkBoxesList.add(chckbxNewCheckBox_18);
		checkBoxesList.add(chckbxNewCheckBox_19);
		checkBoxesList.add(chckbxNewCheckBox_20);
		checkBoxesList.add(chckbxNewCheckBox_21);
		checkBoxesList.add(chckbxNewCheckBox_22);
		checkBoxesList.add(chckbxNewCheckBox_23);
		checkBoxesList.add(chckbxNewCheckBox_24);
		checkBoxesList.add(chckbxNewCheckBox_25);
		checkBoxesList.add(chckbxNewCheckBox_26);
		checkBoxesList.add(chckbxNewCheckBox_27);
		checkBoxesList.add(chckbxNewCheckBox_28);
		checkBoxesList.add(chckbxNewCheckBox_29);
		checkBoxesList.add(chckbxDatabasemanagers);
		checkBoxesList.add(chckbxDocumentationtools);
		checkBoxesList.add(chckbxWebshops);
		checkBoxesList.add(chckbxNewCheckBox);
	}
	private void initWhatToFingerprint(){
		
		for(JCheckBox checkBox:checkBoxesList){
			if(checkBox.isSelected()){
				System.out.println(checkBox.getText());
				WhatToFingerprint.add(checkBox.getText());
			}
		}
	}
	public ArrayList<String> getWhatToFingerprint(){
		return WhatToFingerprint;
	}
	@Override
	public void actionPerformed(ActionEvent e) {
		// TODO Auto-generated method stub
		initWhatToFingerprint();
		this.dispose();
	}
	
}
