/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
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
package org.zaproxy.zap.extension.spiderAjax;

import java.awt.BorderLayout;
import java.awt.EventQueue;
import java.awt.GridBagConstraints;
import java.awt.Rectangle;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.InputEvent;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Vector;

import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JLabel;

import org.apache.commons.httpclient.URIException;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.control.Control.Mode;
import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.extension.history.HistoryFilter;
import org.parosproxy.paros.extension.history.LogPanelCellRenderer;
import org.parosproxy.paros.model.HistoryList;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.httppanel.HttpPanel;
import org.zaproxy.zap.view.ScanStatus;

/**
 * This class creates the Spider AJAX Panel where the found URLs are displayed
 * It has a button to stop the crawler and another one to open the options.
 *
 */
public class SpiderPanel extends AbstractPanel implements Runnable, SpiderListener {
	private static final long serialVersionUID = 1L;
	private static final Logger logger = Logger.getLogger(SpiderPanel.class);
	private javax.swing.JScrollPane scrollLog = null;
	private javax.swing.JList<HistoryReference> listLog = null;
	private javax.swing.JPanel AJAXSpiderPanel = null;
	private javax.swing.JToolBar panelToolbar = null;
	private JLabel filterStatus = null;
	private HttpPanel requestPanel = null;
	private HttpPanel responsePanel = null;
    private ExtensionAjax extension = null;
	private SpiderThread runnable = null;
	private HistoryList list = null;
	private JButton stopScanButton;
	private JButton startScanButton;
	private JButton optionsButton = null;
	
	private ScanStatus scanStatus = null;

	private JLabel activeScansNameLabel = null;
	private JLabel activeScansValueLabel = null;
	private List<String> activeScans = new ArrayList<>();

	private String targetSite;

	/**
	 * This is the default constructor
	 */
	public SpiderPanel(ExtensionAjax e) {
		super();
		this.extension = e;
		initialize();
	}
	
	/**
	 * This method initializes this class and its attributes
	 * 
	 */
	private  void initialize() {
		this.list = new HistoryList();
		this.setLayout(new BorderLayout());
	    if (Model.getSingleton().getOptionsParam().getViewParam().getWmUiHandlingOption() == 0) {
	    	this.setSize(600, 200);
	    }
		this.add(getAJAXSpiderPanel(), java.awt.BorderLayout.CENTER);
        scanStatus = new ScanStatus(
        				new ImageIcon(
        					SpiderPanel.class.getResource("/resource/icon/16/spiderAjax.png")),
        					this.extension.getMessages().getString("spiderajax.panel.title"));
        if (View.isInitialised()) {
        	View.getSingleton().getMainFrame().getMainFooterPanel().addFooterToolbarRightLabel(scanStatus.getCountLabel());
        }

	}
    
    
	/**
	 * This method initializes the scrollLog attribute
	 * 	
	 * @return javax.swing.JScrollPane	
	 */    
	private javax.swing.JScrollPane getScrollLog() {
		if (scrollLog == null) {
			scrollLog = new javax.swing.JScrollPane();
			scrollLog.setViewportView(getListLog());
			scrollLog.setHorizontalScrollBarPolicy(javax.swing.JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
			scrollLog.setVerticalScrollBarPolicy(javax.swing.JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
			scrollLog.setPreferredSize(new java.awt.Dimension(800,200));
			scrollLog.setName("scrollLog");
		}
		return scrollLog;
	}

	
	/**
	 * 
	 * @return the AJAX Spider Panel
	 */
	private javax.swing.JPanel getAJAXSpiderPanel() {
		if (AJAXSpiderPanel == null) {
			
			AJAXSpiderPanel = new javax.swing.JPanel();
			AJAXSpiderPanel.setLayout(new java.awt.GridBagLayout());
			AJAXSpiderPanel.setName("Spider AJAX Panel");
			
			GridBagConstraints gridBagConstraints1 = new GridBagConstraints();
			GridBagConstraints gridBagConstraints2 = new GridBagConstraints();

			gridBagConstraints1.gridx = 0;
			gridBagConstraints1.gridy = 0;
			gridBagConstraints1.weightx = 1.0D;
			gridBagConstraints1.insets = new java.awt.Insets(2,2,2,2);
			gridBagConstraints1.fill = java.awt.GridBagConstraints.HORIZONTAL;
			gridBagConstraints1.anchor = java.awt.GridBagConstraints.NORTHWEST;
			
			gridBagConstraints2.gridx = 0;
			gridBagConstraints2.gridy = 1;
			gridBagConstraints2.weightx = 1.0;
			gridBagConstraints2.weighty = 1.0;
			gridBagConstraints2.insets = new java.awt.Insets(0,0,0,0);
			gridBagConstraints2.fill = java.awt.GridBagConstraints.BOTH;
			gridBagConstraints2.anchor = java.awt.GridBagConstraints.NORTHWEST;

			AJAXSpiderPanel.add(this.getPanelToolbar(), gridBagConstraints1);
			AJAXSpiderPanel.add(getScrollLog(), gridBagConstraints2);

		}
		return AJAXSpiderPanel;
	}
	
	
	/**
	 * 
	 * @return The Stop Scan Button
	 */
	private JButton getStopScanButton() {
		if (stopScanButton == null) {
			stopScanButton = new JButton();
			stopScanButton.setToolTipText(this.extension.getMessages().getString("spiderajax.toolbar.button.stop"));
			stopScanButton.setIcon(new ImageIcon(SpiderPanel.class.getResource("/resource/icon/16/142.png")));
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
	
	
	/**
	 * stops a specific thread
	 * @param site
	 */
	public void stopScan(String site) {
		this.activeScans.remove(site);
		this.setActiveScanLabels();
		this.getStartScanButton().setEnabled(true);
		if (this.activeScans.size() < 1) {
			this.getStopScanButton().setEnabled(false);
		}
		this.runnable.stopSpider();
	}
	
	
	/**
	 * Stops all threads
	 */
	public void stopScan() {
		resetPanelState();
		if (runnable != null) {
			this.runnable.stopSpider();
		}
	}

	private void resetPanelState() {
		this.activeScans = new ArrayList<>();
		this.setActiveScanLabels();
		this.getStartScanButton().setEnabled(true);
		this.getStopScanButton().setEnabled(false);
	}
	
	
	/**
	 * 
	 * @return The Start Scan Button
	 */
	private JButton getStartScanButton() {
		if (startScanButton == null) {
			startScanButton = new JButton();
			startScanButton.setToolTipText(this.extension.getMessages().getString("spiderajax.toolbar.button.start"));
			startScanButton.setIcon(new ImageIcon(SpiderPanel.class.getResource("/resource/icon/16/131.png")));
			startScanButton.setEnabled(false);
			startScanButton.addActionListener(new ActionListener () {

				@Override
				public void actionPerformed(ActionEvent e) {
					//TODO: iniciar aqui el thread
				}

			});

		}
		return startScanButton;
	}
	
	/**
	 * 
	 * @return the History List
	 */
	public HistoryList getHistList(){
		return this.list;
	}
	
	/**
	 * 
	 * @param r history reference
	 * @param msg the http message
	 * @param url the targeted url
	 */
	private void addHistoryUrl(HistoryReference r, HttpMessage msg, String url){
			if(isNewUrl(r, msg) && msg.getRequestHeader().getURI().toString().contains(url)){
				this.getHistList().addElement(r);
			}
		}
	
	/**
	 * 
	 * @param r history reference
	 * @param msg the http message
	 * @return if the url is new or not
	 */
	private boolean isNewUrl(HistoryReference r, HttpMessage msg){
		Enumeration<?> e = this.getHistList().elements();
		while (e.hasMoreElements()) {
			if (e.nextElement().toString().contains(msg.getRequestHeader().getURI().toString())) {
				return false;
			}
		}
		return true;
	}
	
	/**
	 * 
	 * @return the Options Button
	 */
	private JButton getOptionsButton() {
		if (optionsButton == null) {
			optionsButton = new JButton();
			optionsButton.setToolTipText(this.extension.getMessages().getString("spiderajax.options.title"));
			optionsButton.setIcon(new ImageIcon(SpiderPanel.class.getResource("/resource/icon/16/041.png")));
			optionsButton.addActionListener(new ActionListener () {
				@Override
				public void actionPerformed(ActionEvent e) {
					Control.getSingleton().getMenuToolsControl().options(
							extension.getMessages().getString("spiderajax.options.title"));
				}
			});
		}
		return optionsButton;
	}
	
	
	/**
	 * 
	 * @return the panel toolbar
	 */
	private javax.swing.JToolBar getPanelToolbar() {
		if (panelToolbar == null) {
			
			panelToolbar = new javax.swing.JToolBar();
			panelToolbar.setLayout(new java.awt.GridBagLayout());
			panelToolbar.setEnabled(true);
			panelToolbar.setFloatable(false);
			panelToolbar.setRollover(true);
			panelToolbar.setPreferredSize(new java.awt.Dimension(800,30));
			panelToolbar.setFont(new java.awt.Font("Dialog", java.awt.Font.PLAIN, 12));
			panelToolbar.setName("Spider AJAX Toolbar");
			
			GridBagConstraints gridBagConstraints1 = new GridBagConstraints();
			GridBagConstraints gridBagConstraints2 = new GridBagConstraints();
			GridBagConstraints gridBagConstraints3 = new GridBagConstraints();
			GridBagConstraints gridBagConstraints4 = new GridBagConstraints();
			GridBagConstraints gridBagConstraints5 = new GridBagConstraints();
			GridBagConstraints gridBagConstraintsX = new GridBagConstraints();
			GridBagConstraints gridBagConstraints7 = new GridBagConstraints();
			GridBagConstraints gridBagConstraintsy = new GridBagConstraints();

			gridBagConstraints1.gridx = 0;
			gridBagConstraints1.gridy = 0;
			gridBagConstraints1.insets = new java.awt.Insets(0,0,0,0);
			gridBagConstraints1.anchor = java.awt.GridBagConstraints.WEST;
			
			gridBagConstraints2.gridx = 1;
			gridBagConstraints2.gridy = 0;
			gridBagConstraints2.insets = new java.awt.Insets(0,0,0,0);
			gridBagConstraints2.anchor = java.awt.GridBagConstraints.WEST;

			gridBagConstraints3.gridx = 2;
			gridBagConstraints3.gridy = 0;
			gridBagConstraints3.insets = new java.awt.Insets(0,0,0,0);
			gridBagConstraints3.anchor = java.awt.GridBagConstraints.WEST;

			gridBagConstraints4.gridx = 3;
			gridBagConstraints4.gridy = 0;
			gridBagConstraints4.insets = new java.awt.Insets(0,0,0,0);
			gridBagConstraints4.anchor = java.awt.GridBagConstraints.WEST;

			gridBagConstraints5.gridx = 4;
			gridBagConstraints5.gridy = 0;
			gridBagConstraints5.insets = new java.awt.Insets(0,0,0,0);
			gridBagConstraints5.anchor = java.awt.GridBagConstraints.WEST;
			gridBagConstraints7.gridx = 6;
			gridBagConstraints7.gridy = 0;
			gridBagConstraints7.insets = new java.awt.Insets(0,0,0,0);
			gridBagConstraints7.anchor = java.awt.GridBagConstraints.WEST;
			gridBagConstraintsX.gridx = 5;
			gridBagConstraintsX.gridy = 0;
			gridBagConstraintsX.weightx = 1.0;
			gridBagConstraintsX.weighty = 1.0;
			gridBagConstraintsX.insets = new java.awt.Insets(0,0,0,0);
			gridBagConstraintsX.anchor = java.awt.GridBagConstraints.EAST;
			gridBagConstraintsX.fill = java.awt.GridBagConstraints.HORIZONTAL;
			gridBagConstraintsy.gridx = 21;
			gridBagConstraintsy.gridy = 0;
			gridBagConstraintsy.insets = new java.awt.Insets(0,0,0,0);
			gridBagConstraintsy.anchor = java.awt.GridBagConstraints.WEST;
			filterStatus = new JLabel(this.extension.getMessages().getString("spiderajax.panel.subtitle"));
			JLabel t1 = new JLabel();

			panelToolbar.add(filterStatus, gridBagConstraints2);
			panelToolbar.add(getStopScanButton(), gridBagConstraints1);
			panelToolbar.add(getOptionsButton(), gridBagConstraintsy);
			panelToolbar.add(t1, gridBagConstraintsX);
		}
		return panelToolbar;
	}

	/**
	 * This method initializes listLog
	 * 
	 * @return javax.swing.JList
	 */
	private javax.swing.JList<HistoryReference> getListLog() {
		if (listLog == null) {
			listLog = new javax.swing.JList<>(getHistList());
			listLog.setDoubleBuffered(true);
			listLog.setCellRenderer(getLogPanelCellRenderer());
			listLog.setSelectionMode(javax.swing.ListSelectionModel.SINGLE_INTERVAL_SELECTION);
			listLog.setName("ListLog");
			listLog.setFont(new java.awt.Font("Default", java.awt.Font.PLAIN,
					12));
			listLog.setFixedCellHeight(16); // Significantly speeds up rendering
			listLog.addMouseListener(new java.awt.event.MouseAdapter() {
				@Override
				public void mousePressed(java.awt.event.MouseEvent e) {
					mouseClicked(e);
				}

				@Override
				public void mouseReleased(java.awt.event.MouseEvent e) {
					mouseClicked(e);
				}

				@Override
				public void mouseClicked(java.awt.event.MouseEvent e) {
					// right mouse button action
					if ((e.getModifiers() & InputEvent.BUTTON3_MASK) != 0
							|| e.isPopupTrigger()) {

						// ZAP: Select history list item on right click
						int Idx = listLog.locationToIndex(e.getPoint());
						if (Idx >= 0) {
							Rectangle Rect = listLog.getCellBounds(Idx, Idx);
							Idx = Rect.contains(e.getPoint().x, e.getPoint().y) ? Idx
									: -1;
						}
						if (Idx < 0
								|| !listLog.getSelectionModel()
										.isSelectedIndex(Idx)) {
							listLog.getSelectionModel().clearSelection();
							if (Idx >= 0) {
								listLog.getSelectionModel()
										.setSelectionInterval(Idx, Idx);
							}
						}

						View.getSingleton().getPopupMenu()
								.show(e.getComponent(), e.getX(), e.getY());
						return;
					}

					if ((e.getModifiers() & InputEvent.BUTTON1_MASK) != 0
							&& e.getClickCount() > 1) { // double click
						requestPanel.setTabFocus();
						return;
					}
				}
			});

			listLog.addListSelectionListener(new javax.swing.event.ListSelectionListener() {

				
				@Override
				public void valueChanged(javax.swing.event.ListSelectionEvent e) {
					// ZAP: Changed to only display the message when there are
					// no more selection changes.
					if (!e.getValueIsAdjusting()) {
						if (listLog.getSelectedValue() == null) {
							return;
						}

						final HistoryReference historyRef = listLog
								.getSelectedValue();

						readAndDisplay(historyRef);
					}
				}
			});
		}
		return listLog;
	}

	private Vector<HistoryReference> displayQueue = new Vector<>();
	private Thread thread = null;
	private LogPanelCellRenderer logPanelCellRenderer = null;
	
	/**
	 * @param  the history reference to display
	 */
	protected void display(final HistoryReference historyRef) {
		this.readAndDisplay(historyRef);
		for (int i = 0; i < listLog.getModel().getSize(); i++) {
			if (listLog.getModel().getElementAt(i)
					.getHistoryId() == historyRef.getHistoryId()) {
				listLog.setSelectedIndex(i);
				listLog.ensureIndexIsVisible(i);
				break;
			}
		}
	}
	
	
	/**
	 * clear and displays the queue
	 */
	public void clearDisplayQueue() {
		synchronized (displayQueue) {
			displayQueue.clear();
		}
	}
	
	
	/**
	 * @param 
	 */
	private void readAndDisplay(final HistoryReference historyRef) {

		synchronized (displayQueue) {

			if (displayQueue.size() > 0) {
				displayQueue.clear();
			}
			displayQueue.add(historyRef);
		}

		if (thread != null && thread.isAlive()) {
			return;
		}
		thread = new Thread(this);
		thread.setPriority(Thread.NORM_PRIORITY);
		thread.start();
	}

	/**
	 * @param
	 */
	public void setDisplayPanel(HttpPanel requestPanel, HttpPanel responsePanel) {
		this.requestPanel = requestPanel;
		this.responsePanel = responsePanel;

	}    

	
	/**
	 * 
	 * @param msg the httpmessage to display
	 */
	private void displayMessage(HttpMessage msg) {

		if (msg.getRequestHeader().isEmpty()) {
			requestPanel.clearView(true);
		} else {
			requestPanel.setMessage(msg);
		}

		if (msg.getResponseHeader().isEmpty()) {
			responsePanel.clearView(false);
		} else {
			responsePanel.setMessage(msg, true);
		}
	}
	
	/**
	 *
	 */
	@Override
	public void run() {
		HistoryReference ref = null;
		int count = 0;
		do {
			synchronized (displayQueue) {
				count = displayQueue.size();
				if (count == 0) {
					break;
				}

				ref = displayQueue.get(0);
				displayQueue.remove(0);
			}
			try {
				final HttpMessage msg = ref.getHttpMessage();
				EventQueue.invokeAndWait(new Runnable() {
					@Override
					public void run() {
						displayMessage(msg);
						listLog.requestFocus();
					}
				});

			} catch (Exception e) {
				// ZAP: Added logging.
				logger.error(e.getMessage(), e);
			}
			// wait some time to allow another selection event to be triggered
			try {
				Thread.sleep(200);
			} catch (Exception e) {
			}
		} while (true);

	}

	
	/**
	 * This method initializes logPanelCellRenderer
	 * 
	 * @return org.parosproxy.paros.extension.history.LogPanelCellRenderer
	 */
	private LogPanelCellRenderer getLogPanelCellRenderer() {
		if (logPanelCellRenderer == null) {
			logPanelCellRenderer = new LogPanelCellRenderer();
			if (Model.getSingleton().getOptionsParam().getViewParam()
					.getWmUiHandlingOption() == 0) {
				logPanelCellRenderer.setSize(new java.awt.Dimension(328, 21));
			}
			logPanelCellRenderer.setBackground(java.awt.Color.white);
			logPanelCellRenderer.setFont(new java.awt.Font("MS Sans Serif",
					java.awt.Font.PLAIN, 12));
		}
		return logPanelCellRenderer;
	}

	/**
	 * 
	 * @param filter the history filter
	 */
	public void setFilterStatus(HistoryFilter filter) {
		filterStatus.setText(filter.toShortString());
		filterStatus.setToolTipText(filter.toLongString());
	}

	
	/**
	 * 
	 * @param site the targeted site
	 * @param inScope if it is in scope
	 */
	public void startScan(String site, boolean inScope) {
		try {
			this.runnable = extension.createSpiderThread(site, inScope, this);
		} catch (URIException e) {
			logger.error(e);
			return;
		}
		this.getStartScanButton().setEnabled(false);
		this.getStopScanButton().setEnabled(true);
		this.activeScans.add(site);
		this.setActiveScanLabels();
		this.getHistList().clear();
		this.targetSite = site;
		try {
			new Thread(runnable).start();
		} catch (Exception e) {
			logger.error(e);
		}
	}

	/**
	 * @return the active scans name label
	 */
	private JLabel getActiveScansNameLabel() {
		if (activeScansNameLabel == null) {
			activeScansNameLabel = new javax.swing.JLabel();
			activeScansNameLabel.setText(Constant.messages.getString("spiderajax.panel.toolbar.currentscans.label"));
		}
		return activeScansNameLabel;
	}
	
	
	/**
	 * 
	 * @return he number of active scans
	 */
	private JLabel getActiveScansValueLabel() {
		if (activeScansValueLabel == null) {
			activeScansValueLabel = new javax.swing.JLabel();
			activeScansValueLabel.setText(""+activeScans.size());
		}
		return activeScansValueLabel;
	}
	
	/**
	 * sets the number of active scans
	 */
	private void setActiveScanLabels() {
		getActiveScansValueLabel().setText(""+activeScans.size());
		StringBuilder sb = new StringBuilder();
		Iterator <String> iter = activeScans.iterator();
		sb.append("<html>");
		while (iter.hasNext()) {
			sb.append(iter.next());
			sb.append("<br>");
		}
		sb.append("</html>");
		
		final String toolTip = sb.toString();
		
		getActiveScansNameLabel().setToolTipText(toolTip);
		getActiveScansValueLabel().setToolTipText(toolTip);
		
		scanStatus.setScanCount(activeScans.size());
	}
	
	ScanStatus getScanStatus() {
		return scanStatus;
	}
	
	public void reset() {
		stopScan();
		this.getHistList().clear();
	}
	
	
	public void sessionModeChanged(Mode mode) {
		switch (mode) {
		case standard:
		case protect:
			break;
		case safe:
			stopScan();
		}
	}

	@Override
	public void spiderStarted() {
	}

	@Override
	public void foundMessage(HistoryReference historyReference, HttpMessage httpMessage) {
		addHistoryUrl(historyReference, httpMessage, targetSite);
	}

	@Override
	public void spiderStopped() {
		resetPanelState();
	}

}

