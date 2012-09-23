/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 * 
 * Copyright 2010 psiinon@gmail.com
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); 
 * you may not use this file except in compliance with the License. 
 * You may obtain a copy of the License at 
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0 
 *   
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS, 
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
 * See the License for the specific language governing permissions and 
 * limitations under the License. 
 */
package org.zaproxy.zap.extension.tokengen;

import java.awt.CardLayout;
import java.awt.EventQueue;
import java.awt.GridBagConstraints;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;

import javax.swing.DefaultListModel;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.JScrollPane;
import javax.swing.JTextPane;
import javax.swing.JToggleButton;
import javax.swing.JToolBar;
import javax.swing.ListCellRenderer;
import javax.swing.SwingUtilities;

import org.apache.log4j.Logger;
import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.httppanel.HttpPanel;
import org.zaproxy.zap.extension.search.SearchMatch;
import org.zaproxy.zap.view.ScanStatus;
/**
 *
 * To change the template for this generated type comment go to
 * Window - Preferences - Java - Code Generation - Code and Comments
 */
public class TokenPanel extends AbstractPanel {
	
	private static final long serialVersionUID = 1L;

	public static final String PANEL_NAME = "tokenpanel";
	
	private ExtensionTokenGen extension = null;
	private JPanel panelCommand = null;
	private JToolBar panelToolbar = null;
	private JScrollPane jScrollPane = null;
    private TokenPanelCellRenderer portPanelCellRenderer = null;
	private DefaultListModel<HttpMessage> resultsModel  = new DefaultListModel<>();
	private JTextPane initialMessage = null;

	private JButton stopScanButton = null;
	private JToggleButton pauseScanButton = null;
	private JList<HttpMessage> tokenResultList = null;
	private JProgressBar progressBar = null;
	private JButton loadButton = null;
	private JButton saveButton = null;

	private HttpPanel requestPanel = null;
	private HttpPanel responsePanel = null;

	private ScanStatus scanStatus = null;

    private static Logger log = Logger.getLogger(TokenPanel.class);
    
    public TokenPanel(ExtensionTokenGen extension, TokenParam tokenParam) {
        super();
        this.extension = extension;
 		initialize();
    }

	/**
	 * This method initializes this
	 */
	private  void initialize() {
        this.setLayout(new CardLayout());
        this.setSize(474, 251);
        this.setName(ExtensionTokenGen.messages.getString("token.panel.title"));
		this.setIcon(new ImageIcon(getClass().getResource("/resource/icon/fugue/barcode.png")));
        this.add(getPanelCommand(), getPanelCommand().getName());
        
        scanStatus = new ScanStatus(
        				new ImageIcon(
        					getClass().getResource("/resource/icon/fugue/barcode.png")),
        					ExtensionTokenGen.messages.getString("token.panel.title"));
       
        View.getSingleton().getMainFrame().getMainFooterPanel().addFooterToolbarRightLabel(scanStatus.getCountLabel());

	}
	
	/**
	 * This method initializes panelCommand	
	 * 	
	 * @return javax.swing.JPanel	
	 */    
	private javax.swing.JPanel getPanelCommand() {
		if (panelCommand == null) {

			panelCommand = new javax.swing.JPanel();
			panelCommand.setLayout(new java.awt.GridBagLayout());
			panelCommand.setName("TokenGen");
			
			GridBagConstraints gridBagConstraints1 = new GridBagConstraints();
			GridBagConstraints gridBagConstraints2 = new GridBagConstraints();

			gridBagConstraints1.gridx = 0;
			gridBagConstraints1.gridy = 0;
			gridBagConstraints1.insets = new java.awt.Insets(2,2,2,2);
			gridBagConstraints1.anchor = java.awt.GridBagConstraints.NORTHWEST;
			gridBagConstraints1.fill = java.awt.GridBagConstraints.HORIZONTAL;
			gridBagConstraints1.weightx = 1.0D;
			
			gridBagConstraints2.gridx = 0;
			gridBagConstraints2.gridy = 1;
			gridBagConstraints2.weightx = 1.0;
			gridBagConstraints2.weighty = 1.0;
			gridBagConstraints2.fill = java.awt.GridBagConstraints.BOTH;
			gridBagConstraints2.insets = new java.awt.Insets(0,0,0,0);
			gridBagConstraints2.anchor = java.awt.GridBagConstraints.NORTHWEST;
			
			panelCommand.add(this.getPanelToolbar(), gridBagConstraints1);
			panelCommand.add(getJScrollPane(), gridBagConstraints2);
			
		}
		return panelCommand;
	}
	/**/

	private javax.swing.JToolBar getPanelToolbar() {
		if (panelToolbar == null) {
			
			panelToolbar = new javax.swing.JToolBar();
			panelToolbar.setLayout(new java.awt.GridBagLayout());
			panelToolbar.setEnabled(true);
			panelToolbar.setFloatable(false);
			panelToolbar.setRollover(true);
			panelToolbar.setPreferredSize(new java.awt.Dimension(800,30));
			panelToolbar.setFont(new java.awt.Font("Dialog", java.awt.Font.PLAIN, 12));
			panelToolbar.setName("TokenToolbar");
			
			GridBagConstraints gridBagConstraints5 = new GridBagConstraints();
			GridBagConstraints gridBagConstraints6 = new GridBagConstraints();
			GridBagConstraints gridBagConstraints7 = new GridBagConstraints();
			GridBagConstraints gridBagConstraints8 = new GridBagConstraints();
			GridBagConstraints gridBagConstraints9 = new GridBagConstraints();
			GridBagConstraints gridBagConstraints10 = new GridBagConstraints();
			//Dummy
			GridBagConstraints gridBagConstraintsx = new GridBagConstraints();

			gridBagConstraints5.gridx = 4;
			gridBagConstraints5.gridy = 0;
			gridBagConstraints5.insets = new java.awt.Insets(0,0,0,0);
			gridBagConstraints5.anchor = java.awt.GridBagConstraints.WEST;

			gridBagConstraints6.gridx = 5;
			gridBagConstraints6.gridy = 0;
			gridBagConstraints6.insets = new java.awt.Insets(0,0,0,0);
			gridBagConstraints6.anchor = java.awt.GridBagConstraints.WEST;

			gridBagConstraints7.gridx = 6;
			gridBagConstraints7.gridy = 0;
			gridBagConstraints7.insets = new java.awt.Insets(0,0,0,0);
			gridBagConstraints7.anchor = java.awt.GridBagConstraints.WEST;

			gridBagConstraints8.gridx = 7;
			gridBagConstraints8.gridy = 0;
			gridBagConstraints8.weightx = 1.0;
			gridBagConstraints8.weighty = 1.0;
			gridBagConstraints8.insets = new java.awt.Insets(0,5,0,5);	// Slight indent
			gridBagConstraints8.anchor = java.awt.GridBagConstraints.WEST;
			gridBagConstraints8.fill = java.awt.GridBagConstraints.HORIZONTAL;

			gridBagConstraints9.gridx = 8;
			gridBagConstraints9.gridy = 0;
			gridBagConstraints9.insets = new java.awt.Insets(0,0,0,0);
			gridBagConstraints9.anchor = java.awt.GridBagConstraints.EAST;
			

			gridBagConstraints10.gridx = 9;
			gridBagConstraints10.gridy = 0;
			gridBagConstraints10.insets = new java.awt.Insets(0,0,0,0);
			gridBagConstraints10.anchor = java.awt.GridBagConstraints.EAST;
			

			gridBagConstraintsx.gridx = 10;
			gridBagConstraintsx.gridy = 0;
			gridBagConstraintsx.weightx = 1.0;
			gridBagConstraintsx.weighty = 1.0;
			gridBagConstraintsx.insets = new java.awt.Insets(0,0,0,0);
			gridBagConstraintsx.anchor = java.awt.GridBagConstraints.WEST;
			

			JLabel t1 = new JLabel();

			panelToolbar.add(getPauseScanButton(), gridBagConstraints6);
			panelToolbar.add(getStopScanButton(), gridBagConstraints7);
			panelToolbar.add(getProgressBar(), gridBagConstraints8);
			panelToolbar.add(getLoadButton(), gridBagConstraints9);
			panelToolbar.add(getSaveButton(), gridBagConstraints10);

			panelToolbar.add(t1, gridBagConstraintsx);
		}
		return panelToolbar;
	}
	
	private JProgressBar getProgressBar() {
		if (progressBar == null) {
			progressBar = new JProgressBar(0, 100);	// Max will change as scan progresses
			progressBar.setValue(0);
			progressBar.setStringPainted(true);
			progressBar.setEnabled(false);
		}
		return progressBar;
	}

	private JButton getStopScanButton() {
		if (stopScanButton == null) {
			stopScanButton = new JButton();
			stopScanButton.setToolTipText(ExtensionTokenGen.messages.getString("token.toolbar.button.stop"));
			stopScanButton.setIcon(new ImageIcon(getClass().getResource("/resource/icon/16/142.png")));
			stopScanButton.setEnabled(false);
			stopScanButton.addActionListener(new ActionListener () {
				@Override
				public void actionPerformed(ActionEvent e) {
					stopScan();
				}
			});
		}
		return stopScanButton;
	}

	private JToggleButton getPauseScanButton() {
		if (pauseScanButton == null) {
			pauseScanButton = new JToggleButton();
			pauseScanButton.setToolTipText(ExtensionTokenGen.messages.getString("token.toolbar.button.pause"));
			pauseScanButton.setIcon(new ImageIcon(getClass().getResource("/resource/icon/16/141.png")));
			pauseScanButton.setEnabled(false);
			pauseScanButton.addActionListener(new ActionListener () {
				@Override
				public void actionPerformed(ActionEvent e) {
					pauseScan();
				}
			});
		}
		return pauseScanButton;
	}

	private JButton getLoadButton() {
		if (loadButton == null) {
			loadButton = new JButton();
			loadButton.setToolTipText(ExtensionTokenGen.messages.getString("token.toolbar.button.load"));
			loadButton.setIcon(new ImageIcon(getClass().getResource("/resource/icon/16/047.png")));
			loadButton.setEnabled(true);
			loadButton.addActionListener(new ActionListener () {
				@Override
				public void actionPerformed(ActionEvent e) {
					loadTokens();
				}
			});
		}
		return loadButton;
	}

	private JButton getSaveButton() {
		if (saveButton == null) {
			saveButton = new JButton();
			saveButton.setToolTipText(ExtensionTokenGen.messages.getString("token.toolbar.button.save"));
			saveButton.setIcon(new ImageIcon(getClass().getResource("/resource/icon/16/096.png")));
			saveButton.setEnabled(false);
			saveButton.addActionListener(new ActionListener () {
				@Override
				public void actionPerformed(ActionEvent e) {
					saveTokens();
				}
			});
		}
		return saveButton;
	}

	private JScrollPane getJScrollPane() {
		if (jScrollPane == null) {
			jScrollPane = new JScrollPane();
			jScrollPane.setViewportView(getInitialMessage());
			jScrollPane.setFont(new java.awt.Font("Dialog", java.awt.Font.PLAIN, 11));
			jScrollPane.setHorizontalScrollBarPolicy(javax.swing.JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
		}
		return jScrollPane;
	}
	
	private JTextPane getInitialMessage() {
		if (initialMessage == null) {
			initialMessage = new JTextPane();
			initialMessage.setEditable(false);
			initialMessage.setFont(new java.awt.Font("Dialog", java.awt.Font.PLAIN, 12));
			initialMessage.setContentType("text/html");
			initialMessage.setText(ExtensionTokenGen.messages.getString("token.label.initialMessage"));
		}
		
		return initialMessage;
	}

	private void resetTokenResultList() {
		resultsModel = new DefaultListModel<>();
		getTokenResultList().setModel(resultsModel);
	}
	
	public int getTokenResultsSize() {
		return this.resultsModel.getSize();
	}
	
	protected void addTokenResult(final HttpMessage msg) {
		
		if (EventQueue.isDispatchThread()) {
			resultsModel.addElement(msg);
			getProgressBar().setValue(getProgressBar().getValue() + 1);
		    return;
		}
		try {
			EventQueue.invokeLater(new Runnable() {
				@Override
				public void run() {
					resultsModel.addElement(msg);
					getProgressBar().setValue(getProgressBar().getValue() + 1);
				}
			});
		} catch (Exception e) {
		}
	}

	private JList<HttpMessage> getTokenResultList() {
		if (tokenResultList == null) {
			tokenResultList = new JList<>();
			tokenResultList.setDoubleBuffered(true);
			tokenResultList.setCellRenderer(getPortPanelCellRenderer());
			tokenResultList.setSelectionMode(javax.swing.ListSelectionModel.SINGLE_INTERVAL_SELECTION);
			tokenResultList.setName(PANEL_NAME);
			tokenResultList.setFont(new java.awt.Font("Default", java.awt.Font.PLAIN, 12));
			
			tokenResultList.setFixedCellHeight(16);	// Significantly speeds up rendering

	        tokenResultList.addMouseListener(new java.awt.event.MouseAdapter() { 
				@Override
				public void mousePressed(java.awt.event.MouseEvent e) {    
				    if (SwingUtilities.isRightMouseButton(e)) {
				        View.getSingleton().getPopupMenu().show(e.getComponent(), e.getX(), e.getY());
				    }	
				}
			});

			tokenResultList.addListSelectionListener(new javax.swing.event.ListSelectionListener() { 

				@Override
				public void valueChanged(javax.swing.event.ListSelectionEvent e) {
				    if (tokenResultList.getSelectedValue() == null) {
				        return;
				    }
                    
				    displayMessage(tokenResultList.getSelectedValue());
				}
			});
			
			resetTokenResultList();
		}
		return tokenResultList;
	}

    private void displayMessage(HttpMessage msg) {
		try {
			requestPanel.setMessage(msg);
			responsePanel.setMessage(msg);
			
	        String note = msg.getNote();
	        if (note != null && note.length() > 0) {
	        	int startIndex = msg.getResponseHeader().toString().indexOf(note);
	        	if (startIndex >= 0) {
	        		// Found the exact pattern - highlight it
	        		SearchMatch sm = new SearchMatch(msg, SearchMatch.Location.RESPONSE_HEAD, startIndex, startIndex + note.length());
	        		responsePanel.setTabFocus();
	        		responsePanel.requestFocus();
					responsePanel.highlightHeader(sm);
	        	} else {
		        	startIndex = msg.getResponseBody().toString().indexOf(note);
		        	if (startIndex >= 0) {
		        		// Found the exact pattern - highlight it
		        		SearchMatch sm = new SearchMatch(msg, SearchMatch.Location.RESPONSE_BODY, startIndex, startIndex + note.length());
		        		responsePanel.setTabFocus();
		        		responsePanel.requestFocus();
						responsePanel.highlightBody(sm);
		        	}
	        	}
	        }
		} catch (Exception e) {
			log.error("Failed to access message ", e);
		}
    }

	private ListCellRenderer<HttpMessage> getPortPanelCellRenderer() {
        if (portPanelCellRenderer == null) {
            portPanelCellRenderer = new TokenPanelCellRenderer();
            portPanelCellRenderer.setSize(new java.awt.Dimension(328,21));
            portPanelCellRenderer.setBackground(java.awt.Color.white);
            portPanelCellRenderer.setFont(new java.awt.Font("MS Sans Serif", java.awt.Font.PLAIN, 12));
        }
        return portPanelCellRenderer;
	}

	private void stopScan() {
		log.debug("Stopping token generation");
		extension.stopTokenGeneration ();
	}
	
	private void loadTokens() {
		JFileChooser chooser = new JFileChooser(Model.getSingleton().getOptionsParam().getUserDirectory());
	    int rc = chooser.showOpenDialog(View.getSingleton().getMainFrame());
	    if(rc == JFileChooser.APPROVE_OPTION) {
			try {
	    		File file = chooser.getSelectedFile();
	    		if (file == null) {
	    			return;
	    		}
                Model.getSingleton().getOptionsParam().setUserDirectory(chooser.getCurrentDirectory());
		
				CharacterFrequencyMap cfm = new CharacterFrequencyMap();
				cfm.load(file);
				this.extension.showAnalyseTokensDialog(cfm);
				
			} catch (Exception e) {
				View.getSingleton().showWarningDialog(ExtensionTokenGen.messages.getString("token.generate.load.error"));
	            log.error(e.getMessage(), e);
			}
	    }
	}
	
	private void saveTokens() {
		JFileChooser chooser = new JFileChooser(Model.getSingleton().getOptionsParam().getUserDirectory());
		File file = null;
	    int rc = chooser.showSaveDialog(View.getSingleton().getMainFrame());
	    if(rc == JFileChooser.APPROVE_OPTION) {
			try {
	    		file = chooser.getSelectedFile();
	    		if (file == null) {
	    			return;
	    		}
                Model.getSingleton().getOptionsParam().setUserDirectory(chooser.getCurrentDirectory());
		
				CharacterFrequencyMap cfm = new CharacterFrequencyMap();
		
				for (int i=0; i < this.resultsModel.getSize(); i++) {
					HttpMessage msg = this.resultsModel.get(i);
					if (msg.getNote() != null) {
						cfm.addToken(msg.getNote());
					}
				}
				
				cfm.save(file);
				
			} catch (Exception e) {
				View.getSingleton().showWarningDialog(ExtensionTokenGen.messages.getString("token.generate.save.error"));
	            log.error(e.getMessage(), e);
			}
	    }
	}

	private void pauseScan() {
		if (getPauseScanButton().getModel().isSelected()) {
			log.debug("Pausing token generation");
			extension.pauseTokenGeneration();
			getPauseScanButton().setToolTipText(ExtensionTokenGen.messages.getString("token.toolbar.button.unpause"));
		} else {
			log.debug("Resuming token generation");
			extension.resumeTokenGeneration();
			getPauseScanButton().setToolTipText(ExtensionTokenGen.messages.getString("token.toolbar.button.pause"));

		}
	}

	public void scanStarted(int reqCount) {
		getProgressBar().setValue(0);
		getProgressBar().setMaximum(reqCount);
		
		this.getJScrollPane().setViewportView(getTokenResultList());
		this.setTabFocus();
		resetTokenResultList();

		getProgressBar().setEnabled(true);
		getStopScanButton().setEnabled(true);
		getPauseScanButton().setEnabled(true);
		getSaveButton().setEnabled(false);
		scanStatus.incScanCount();
	}

	public void scanFinshed() {
		getStopScanButton().setEnabled(false);
		getPauseScanButton().setEnabled(false);
		getPauseScanButton().setSelected(false);
		getPauseScanButton().setToolTipText(ExtensionTokenGen.messages.getString("token.toolbar.button.pause"));
		if (getTokenResultsSize() > 0) {
			getSaveButton().setEnabled(true);
		}
		getProgressBar().setEnabled(false);
		scanStatus.decScanCount();
	}

	public void reset() {
		resetTokenResultList();
		getStopScanButton().setEnabled(false);
		getProgressBar().setEnabled(false);
		getProgressBar().setValue(0);
		
	}

    public void setDisplayPanel(HttpPanel requestPanel, HttpPanel responsePanel) {
        this.requestPanel = requestPanel;
        this.responsePanel = responsePanel;

    }

}
