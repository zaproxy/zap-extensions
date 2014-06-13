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
package org.zaproxy.zap.extension.accessControl;

import java.awt.Component;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;

import javax.swing.ImageIcon;
import javax.swing.JScrollPane;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;

import org.apache.log4j.Logger;
import org.jdesktop.swingx.JXTable;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.accessControl.AccessControlResultsTableModel.AccessControlResultsTableEntry;
import org.zaproxy.zap.extension.accessControl.AccessControlScannerThread.AccessControlScanListener;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.scan.BaseScannerThreadManager;
import org.zaproxy.zap.users.User;
import org.zaproxy.zap.view.panels.AbstractScanToolbarStatusPanel;

/**
 * Under development...
 */
public class AccessControlStatusPanel extends AbstractScanToolbarStatusPanel implements
		AccessControlScanListener {

	private static final long serialVersionUID = 3717381205061196129L;

	private static final String PANEL_NAME = "AccessControlStatusPanel";
	private static final Logger log = Logger.getLogger(AccessControlStatusPanel.class);
	private static final AccessControlResultsTableModel EMPTY_RESULTS_MODEL = new AccessControlResultsTableModel();

	private JXTable resultsTable;
	private JScrollPane workPane;
	private Map<Integer, AccessControlResultsTableModel> resultsModels;
	private AccessControlResultsTableModel currentResultsModel = EMPTY_RESULTS_MODEL;
	private ExtensionAccessControl extension;

	public AccessControlStatusPanel(ExtensionAccessControl extension,
			BaseScannerThreadManager<AccessControlScannerThread> threadManager) {

		super("accessControl", new ImageIcon(
				AccessControlStatusPanel.class.getResource("/resource/icon/16/accessControl.png")),
				threadManager);
		this.extension = extension;
		this.resultsModels = new HashMap<>();
	}

	@Override
	public void scanResultObtained(int contextId, HistoryReference hRef, User user,
			boolean requestAuthorized, String result, String accessRule) {
		getResultsModel(contextId).addEntry(
				new AccessControlResultsTableEntry(hRef, user, requestAuthorized, result, accessRule));
	}

	@Override
	protected Component getWorkPanel() {
		if (workPane == null) {
			workPane = new JScrollPane();
			workPane.setName("AccessControlResultsPane");
			workPane.setViewportView(getScanResultsTable());
			workPane.setFont(new java.awt.Font("Dialog", java.awt.Font.PLAIN, 11));
		}
		return workPane;
	}

	/**
	 * Gets the scan results table.
	 * 
	 * @return the scan results table
	 */
	private JXTable getScanResultsTable() {
		if (resultsTable == null) {
			// Create the table with a default, empty TableModel and the proper settings
			resultsTable = new JXTable(EMPTY_RESULTS_MODEL);
			resultsTable.setColumnSelectionAllowed(false);
			resultsTable.setCellSelectionEnabled(false);
			resultsTable.setRowSelectionAllowed(true);
			resultsTable.setAutoCreateRowSorter(true);
			resultsTable.setColumnControlVisible(true);

			this.setScanResultsTableColumnSizes();

			resultsTable.setName(PANEL_NAME);
			resultsTable.setFont(new java.awt.Font("Dialog", java.awt.Font.PLAIN, 11));
			resultsTable.setDoubleBuffered(true);
			resultsTable.setSelectionMode(javax.swing.ListSelectionModel.SINGLE_SELECTION);
			resultsTable.getSelectionModel().addListSelectionListener(
					new DisplayMessageOnSelectionValueChange());
		}
		return resultsTable;
	}

	protected AccessControlResultsTableModel getResultsModel(int contextId) {
		AccessControlResultsTableModel model = resultsModels.get(contextId);
		if (model == null) {
			model = new AccessControlResultsTableModel();
			resultsModels.put(contextId, model);
		}
		return model;
	}

	protected void displayMessageInHttpPanel(final HttpMessage msg) {
		if (msg == null) {
			return;
		}

		if (msg.getRequestHeader().isEmpty()) {
			View.getSingleton().getRequestPanel().clearView(true);
		} else {
			View.getSingleton().getRequestPanel().setMessage(msg);
		}

		if (msg.getResponseHeader().isEmpty()) {
			View.getSingleton().getResponsePanel().clearView(false);
		} else {
			View.getSingleton().getResponsePanel().setMessage(msg, true);
		}
	}

	@Override
	protected void switchViewForContext(Context context) {
		if (context == null) {
			this.currentResultsModel = EMPTY_RESULTS_MODEL;
			return;
		}

		this.currentResultsModel = getResultsModel(context.getIndex());
		this.getScanResultsTable().setModel(this.currentResultsModel);
		this.setScanResultsTableColumnSizes();
	}

	/**
	 * Sets the results table column sizes.
	 */
	private void setScanResultsTableColumnSizes() {
		resultsTable.getColumnModel().getColumn(0).setMinWidth(40);
		resultsTable.getColumnModel().getColumn(0).setPreferredWidth(50); // id

		resultsTable.getColumnModel().getColumn(1).setMinWidth(40);
		resultsTable.getColumnModel().getColumn(1).setPreferredWidth(50); // method

		resultsTable.getColumnModel().getColumn(2).setMinWidth(240);
		resultsTable.getColumnModel().getColumn(2).setPreferredWidth(800);// url

		resultsTable.getColumnModel().getColumn(3).setMinWidth(40);
		resultsTable.getColumnModel().getColumn(3).setPreferredWidth(50); // code

		resultsTable.getColumnModel().getColumn(4).setMinWidth(70);
		resultsTable.getColumnModel().getColumn(4).setPreferredWidth(100); // user

		resultsTable.getColumnModel().getColumn(5).setMinWidth(40);
		resultsTable.getColumnModel().getColumn(5).setPreferredWidth(50); // authorized

		resultsTable.getColumnModel().getColumn(6).setMinWidth(60);
		resultsTable.getColumnModel().getColumn(6).setPreferredWidth(100); // access rule

		resultsTable.getColumnModel().getColumn(7).setMinWidth(60);
		resultsTable.getColumnModel().getColumn(7).setPreferredWidth(100); // result
	}

	@Override
	public void scanStarted(int contextId) {
		super.scanStarted(contextId);
		getResultsModel(contextId).clear();
	}

	@Override
	protected void startScan(Context context) {
		log.info("Access Control start on Context: " + context);
		extension.showScanOptionsDialog(context);
	}

	public HistoryReference getSelectedHistoryReference() {
		final int selectedRow = resultsTable.getSelectedRow();
		if (selectedRow != -1 && currentResultsModel != null) {
			return currentResultsModel.getEntry(selectedRow).getHistoryReference();
		}
		return null;
	}

	/**
	 * Utility class used to display the currently selected message in the HttpRequest/Response
	 * panels.
	 */
	protected class DisplayMessageOnSelectionValueChange implements ListSelectionListener {

		@Override
		public void valueChanged(final ListSelectionEvent evt) {
			if (!evt.getValueIsAdjusting()) {
				HistoryReference hRef = getSelectedHistoryReference();
				if (hRef != null) {
					try {
						displayMessageInHttpPanel(hRef.getHttpMessage());
					} catch (HttpMalformedHeaderException | SQLException e) {
						log.error(e.getMessage(), e);
					}
				}
			}
		}
	}

}
