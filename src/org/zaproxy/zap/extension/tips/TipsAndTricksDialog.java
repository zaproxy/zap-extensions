/*
 *
 * Paros and its related class files.
 * 
 * Paros is an HTTP/HTTPS proxy for assessing web application security.
 * Copyright (C) 2003-2004 Chinotec Technologies Company
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the Clarified Artistic License
 * as published by the Free Software Foundation.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * Clarified Artistic License for more details.
 * 
 * You should have received a copy of the Clarified Artistic License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */
// ZAP: 2011/04/16 i18n
// ZAP: 2012/04/23 Added @Override annotation to all appropriate methods.
// ZAP: 2012/05/03 Changed the method find to check if txtComp is null.
// ZAP: 2014/01/30 Issue 996: Ensure all dialogs close when the escape key is pressed (copy tidy up)

package org.zaproxy.zap.extension.tips;

import java.awt.Frame;
import java.awt.GridBagLayout;
import java.awt.HeadlessException;
import java.awt.Point;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.ScrollPaneConstants;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.AbstractDialog;
import org.parosproxy.paros.model.Model;
import org.zaproxy.zap.utils.ZapTextArea;
import org.zaproxy.zap.view.LayoutHelper;

public class TipsAndTricksDialog extends AbstractDialog {

	private static final long serialVersionUID = -1L;

	private ExtensionTipsAndTricks ext;
	private JPanel jPanel = null;
	private JButton btnNextTip = null;
	private JButton btnClose = null;
	private ZapTextArea txtTip = null;
	private JScrollPane scrollPane = null;
    private JCheckBox showOnStart = null;
	private JPanel jPanel1 = null;
	private String lastTip = null;
    
    /**
     * @throws HeadlessException
     */
    public TipsAndTricksDialog(ExtensionTipsAndTricks ext, Frame parent) throws HeadlessException {
        super(parent, true);
 		this.ext = ext;
 		initialize();
    }

	/**
	 * This method initializes this
	 */
	private void initialize() {
        this.setVisible(false);
        this.setResizable(false);
        this.setModalityType(ModalityType.APPLICATION_MODAL);	// Block all other windows
        this.setTitle(Constant.messages.getString("tips.dialog.title"));
        this.setContentPane(getJPanel());
	    if (Model.getSingleton().getOptionsParam().getViewParam().getWmUiHandlingOption() == 0) {
	    	this.setSize(300, 235);
	    }
        centreDialog();
        this.getRootPane().setDefaultButton(btnNextTip);
        pack();
	}
	
	public void displayTip() {
		String tip = ext.getRandomTip();
		while (tip.equals(lastTip)) {
			// Make sure we always get e new tip
			tip = ext.getRandomTip();
		}
		this.getTxtTip().setText(tip);
		// Scroll to the top
		this.getScrollPane().getViewport().setViewPosition(new Point(0,0));
		lastTip = tip;
		this.setVisible(true);
	}
	
	/**
	 * This method initializes jPanel	
	 * 	
	 * @return javax.swing.JPanel	
	 */    
	private JPanel getJPanel() {
		if (jPanel == null) {
			jPanel = new JPanel();
			jPanel.setLayout(new GridBagLayout());
			jPanel.add(getScrollPane(), LayoutHelper.getGBC(0, 0, 2, 1.0D, 1.0D));
			jPanel.add(getShowOnStartCheckbox(), LayoutHelper.getGBC(0, 1, 2, 1.0D, 0.0D));
			jPanel.add(new JLabel(), LayoutHelper.getGBC(0, 2, 1, 1.0D, 0.0D));
			jPanel.add(getButtonPanel(), LayoutHelper.getGBC(1, 2, 1, 0.0D, 0.0D));
		}
		return jPanel;
	}
	
    private JCheckBox getShowOnStartCheckbox() {
    	if (showOnStart == null) {
    		showOnStart = new JCheckBox(Constant.messages.getString("tips.checkbox.showOnStart"));
    		showOnStart.setSelected(ext.isShowOnStart());
    	}
    	return showOnStart;
    }

	
	/**
	 * This method initializes btnFind	
	 * 	
	 * @return javax.swing.JButton	
	 */    
	private JButton getNextTipButton() {
		if (btnNextTip == null) {
			btnNextTip = new JButton();
			btnNextTip.setText(Constant.messages.getString("tips.button.nextTip"));
			btnNextTip.addActionListener(new java.awt.event.ActionListener() { 
				@Override
				public void actionPerformed(java.awt.event.ActionEvent e) {    
					displayTip();
				}
			});
		}
		return btnNextTip;
	}
	/**
	 * This method initializes btnCancel	
	 * 	
	 * @return javax.swing.JButton	
	 */    
	private JButton getCloseButton() {
		if (btnClose == null) {
			btnClose = new JButton();
			btnClose.setText(Constant.messages.getString("all.button.close"));
			btnClose.addActionListener(new java.awt.event.ActionListener() { 
				@Override
				public void actionPerformed(java.awt.event.ActionEvent e) {
					ext.setShowOnStart(getShowOnStartCheckbox().isSelected());
				    TipsAndTricksDialog.this.setVisible(false);
				}
			});

		}
		return btnClose;
	}
	
	private JScrollPane getScrollPane() {
		if (scrollPane == null) {
			scrollPane = new JScrollPane();
			scrollPane.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
			scrollPane.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED);
			scrollPane.setMinimumSize(new java.awt.Dimension(300,200));
			scrollPane.setPreferredSize(new java.awt.Dimension(300,200));
			scrollPane.setViewportView(this.getTxtTip());
		}
		return scrollPane;
	}

	/**
	 * This method initializes txtFind	
	 * 	
	 * @return org.zaproxy.zap.utils.ZapTextField	
	 */    
	private ZapTextArea getTxtTip() {
		if (txtTip == null) {
			txtTip = new ZapTextArea();
			txtTip.setEditable(false);
			txtTip.setLineWrap(true);
			txtTip.setWrapStyleWord(true);
		}
		return txtTip;
	}
	/**
	 * This method initializes jPanel1	
	 * 	
	 * @return javax.swing.JPanel	
	 */    
	private JPanel getButtonPanel() {
		if (jPanel1 == null) {
			jPanel1 = new JPanel();
			jPanel1.setMinimumSize(new java.awt.Dimension(300,35));
			jPanel1.add(getCloseButton(), null);
			jPanel1.add(getNextTipButton(), null);
		}
		return jPanel1;
	}
}
