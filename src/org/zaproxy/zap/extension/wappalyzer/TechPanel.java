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
package org.zaproxy.zap.extension.wappalyzer;

import java.awt.CardLayout;
import java.awt.Event;
import java.awt.GridBagConstraints;
import java.awt.Toolkit;
import java.awt.event.KeyEvent;

import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JToolBar;
import javax.swing.KeyStroke;
import javax.swing.SwingUtilities;

import org.jdesktop.swingx.JXTable;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.utils.SortedComboBoxModel;
import org.zaproxy.zap.view.ScanPanel;

public class TechPanel extends AbstractPanel {
	
	private static final long serialVersionUID = 1L;

	public static final String PANEL_NAME = "wapptechpanel";
	
	private ExtensionWappalyzer extension = null;
	private JPanel panelCommand = null;
	private JToolBar panelToolbar = null;
	private JScrollPane jScrollPane = null;

	private String currentSite = null;
	private JComboBox<String> siteSelect = null;
	private SortedComboBoxModel<String> siteModel = new SortedComboBoxModel<>();

	private JXTable techTable = null;
	private TechTableModel techModel = new TechTableModel();
   
    public TechPanel(ExtensionWappalyzer extension) {
        super();
        this.extension = extension;
 		initialize();
    }

	private  void initialize() {
        this.setLayout(new CardLayout());
        this.setSize(474, 251);
        this.setName(Constant.messages.getString("wappalyzer.panel.title"));
		this.setIcon(ExtensionWappalyzer.WAPPALYZER_ICON);
		this.setDefaultAccelerator(KeyStroke.getKeyStroke(
				KeyEvent.VK_T, Toolkit.getDefaultToolkit().getMenuShortcutKeyMask() | Event.ALT_MASK | Event.SHIFT_MASK, false));
		this.setMnemonic(Constant.messages.getChar("wappalyzer.panel.mnemonic"));
        this.add(getPanelCommand(), getPanelCommand().getName());
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
			panelCommand.setName("Params");
			
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

	private javax.swing.JToolBar getPanelToolbar() {
		if (panelToolbar == null) {
			
			panelToolbar = new javax.swing.JToolBar();
			panelToolbar.setLayout(new java.awt.GridBagLayout());
			panelToolbar.setEnabled(true);
			panelToolbar.setFloatable(false);
			panelToolbar.setRollover(true);
			panelToolbar.setPreferredSize(new java.awt.Dimension(800,30));
			panelToolbar.setFont(new java.awt.Font("Dialog", java.awt.Font.PLAIN, 12));
			panelToolbar.setName("WappTechToolbar");
			
			GridBagConstraints gridBagConstraints0 = new GridBagConstraints();
			GridBagConstraints gridBagConstraints1 = new GridBagConstraints();
			GridBagConstraints gridBagConstraints2 = new GridBagConstraints();
			GridBagConstraints gridBagConstraintsx = new GridBagConstraints();

			gridBagConstraints0.gridx = 0;
			gridBagConstraints0.gridy = 0;
			gridBagConstraints0.insets = new java.awt.Insets(0,0,0,0);
			gridBagConstraints0.anchor = java.awt.GridBagConstraints.WEST;
			
			gridBagConstraints1.gridx = 1;
			gridBagConstraints1.gridy = 0;
			gridBagConstraints1.insets = new java.awt.Insets(0,0,0,0);
			gridBagConstraints1.anchor = java.awt.GridBagConstraints.WEST;
			
			gridBagConstraints2.gridx = 2;
			gridBagConstraints2.gridy = 0;
			gridBagConstraints2.insets = new java.awt.Insets(0,0,0,0);
			gridBagConstraints2.anchor = java.awt.GridBagConstraints.WEST;

			gridBagConstraintsx.gridx = 3;
			gridBagConstraintsx.gridy = 0;
			gridBagConstraintsx.weightx = 1.0;
			gridBagConstraintsx.weighty = 1.0;
			gridBagConstraintsx.insets = new java.awt.Insets(0,0,0,0);
			gridBagConstraintsx.anchor = java.awt.GridBagConstraints.EAST;
			gridBagConstraintsx.fill = java.awt.GridBagConstraints.HORIZONTAL;

			JLabel t1 = new JLabel();

			panelToolbar.add(new JLabel(Constant.messages.getString("wappalyzer.toolbar.site.label")), gridBagConstraints1);
			panelToolbar.add(getSiteSelect(), gridBagConstraints2);
			
			panelToolbar.add(t1, gridBagConstraintsx);
		}
		return panelToolbar;
	}

	private JScrollPane getJScrollPane() {
		if (jScrollPane == null) {
			jScrollPane = new JScrollPane();
			jScrollPane.setViewportView(getTechTable());
			jScrollPane.setFont(new java.awt.Font("Dialog", java.awt.Font.PLAIN, 11));
		}
		return jScrollPane;
	}
	
	private void setParamsTableColumnSizes() {
		// Just set the 2 columns that dont need much space and let the rest autosize
		techTable.getColumn(Constant.messages.getString("wappalyzer.table.header.icon")).setMinWidth(25);
		techTable.getColumn(Constant.messages.getString("wappalyzer.table.header.icon")).setPreferredWidth(25);	// icon
		techTable.getColumn(Constant.messages.getString("wappalyzer.table.header.icon")).setMaxWidth(35);

		/* Dont currently support confidence
		techTable.getColumnModel().getColumn(5).setMinWidth(80);
		techTable.getColumnModel().getColumn(5).setMaxWidth(80);
		techTable.getColumnModel().getColumn(5).setPreferredWidth(80);	// confidence
		*/
	}
	
	protected JXTable getTechTable() {
		if (techTable == null) {
			techTable = new JXTable(techModel);

			techTable.setColumnSelectionAllowed(false);
			techTable.setCellSelectionEnabled(false);
			techTable.setRowSelectionAllowed(true);
			techTable.setAutoCreateRowSorter(true);
			techTable.setColumnControlVisible(true);

			this.setParamsTableColumnSizes();

			techTable.setName(PANEL_NAME);
			techTable.setFont(new java.awt.Font("Dialog", java.awt.Font.PLAIN, 11));
			techTable.setDoubleBuffered(true);
			techTable.setSelectionMode(javax.swing.ListSelectionModel.SINGLE_SELECTION);
			techTable.addMouseListener(new java.awt.event.MouseAdapter() { 
			    @Override
			    public void mousePressed(java.awt.event.MouseEvent e) {

					if (SwingUtilities.isRightMouseButton(e)) {

						// Select table item
					    int row = techTable.rowAtPoint( e.getPoint() );
					    if ( row < 0 || !techTable.getSelectionModel().isSelectedIndex( row ) ) {
					    	techTable.getSelectionModel().clearSelection();
					    	if ( row >= 0 ) {
					    		techTable.getSelectionModel().setSelectionInterval( row, row );
					    	}
					    }
						
						View.getSingleton().getPopupMenu().show(e.getComponent(), e.getX(), e.getY());
			        }
			    }
			});
		}
		return techTable;
	}

	private JComboBox<String> getSiteSelect() {
		if (siteSelect == null) {
			siteSelect = new JComboBox<>(siteModel);
			siteSelect.addItem(Constant.messages.getString("params.toolbar.site.select"));
			siteSelect.setSelectedIndex(0);

			siteSelect.addActionListener(new java.awt.event.ActionListener() { 

				@Override
				public void actionPerformed(java.awt.event.ActionEvent e) {    

				    String item = (String) siteSelect.getSelectedItem();
				    if (item != null && siteSelect.getSelectedIndex() > 0) {
				        siteSelected(item);
				    }
				}
			});
		}
		return siteSelect;
	}

	public void addSite(String site) {
		site = ScanPanel.cleanSiteName(site, true);
		if (siteModel.getIndexOf(site) < 0) {
			siteModel.addElement(site);
			if (siteModel.getSize() == 2 && currentSite == null) {
				// First site added, automatically select it
				this.getSiteSelect().setSelectedIndex(1);
				siteSelected(site);
			}
		}
	}
	
	private void siteSelected(String site) {
		site = ScanPanel.cleanSiteName(site, true);
		if (! site.equals(currentSite)) {
			siteModel.setSelectedItem(site);
			techModel = extension.getTechModelForSite(site);
			this.getTechTable().setModel(techModel);
			this.setParamsTableColumnSizes();
			currentSite = site;
		}
	}

	public void nodeSelected(SiteNode node) {
		if (node != null) {
			siteSelected(ScanPanel.cleanSiteName(node, true));
		}
	}

	public void reset() {
		currentSite = null;
		
		siteModel.removeAllElements();
		siteSelect.addItem(Constant.messages.getString("wappalyzer.toolbar.site.select"));
		siteSelect.setSelectedIndex(0);
		
		techModel.removeAllElements();
		techModel.fireTableDataChanged();
		
		techTable.setModel(techModel);

	}
	
	/**
	 * Gets the current selected site.
	 * 
	 * @return the current site
	 */
	public String getCurrentSite(){
		return currentSite;
	}
	
	protected String getSelectedApplicationName() {
		if (this.getTechTable().getSelectedRow() >= 0) {
			return (String) this.getTechTable().getValueAt(this.getTechTable().getSelectedRow(), 1);
		}
		return null;
	}
}
