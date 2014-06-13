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

import org.apache.log4j.Logger;
import org.jdesktop.swingx.JXTable;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
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
	public void scanResultObtained(int contextId, HttpMessage msg, User user, String result, String accessRule) {
		try {
			getResultsModel(contextId).addEntry(
					new AccessControlResultsTableEntry(new HistoryReference(
							Model.getSingleton().getSession(), 0, msg), user, result, accessRule));
		} catch (HttpMalformedHeaderException | SQLException e) {
			e.printStackTrace();
		}
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

			// this.setScanResultsTableColumnSizes();

			resultsTable.setName(PANEL_NAME);
			resultsTable.setFont(new java.awt.Font("Dialog", java.awt.Font.PLAIN, 11));
			resultsTable.setDoubleBuffered(true);
			resultsTable.setSelectionMode(javax.swing.ListSelectionModel.SINGLE_SELECTION);
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

	@Override
	protected void switchViewForContext(Context context) {
		if (context == null) {
			this.currentResultsModel = EMPTY_RESULTS_MODEL;
			return;
		}

		this.currentResultsModel = getResultsModel(context.getIndex());
		this.getScanResultsTable().setModel(this.currentResultsModel);
		// this.setScanResultsTableColumnSizes();
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

}
