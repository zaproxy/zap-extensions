/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 * 
 * Copyright 2011 The ZAP Development team
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
package org.zaproxy.zap.extension.alertReport;

import java.awt.Component;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.swing.JTree;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.TreePath;

import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.extension.ExtensionPopupMenuItem;
import org.parosproxy.paros.view.View;

public class AlertReportExportMenuItem extends ExtensionPopupMenuItem {

	private static final long serialVersionUID = 1L;
	private ExtensionAlertReportExport extension = null;
	//private ExtensionAlert extAlert = null;
	private AlertReportExportPDF reportExportPDF = null;
	private AlertReportExportODT reportExportODT = null;
	private JTree treeAlert = null;
	//private ResourceBundle messages = null;

	/**
	 * @param label
	 */
	public AlertReportExportMenuItem(String label) {
		super(label);
		initialize();
		this.reportExportPDF = new AlertReportExportPDF();
		this.reportExportODT = new AlertReportExportODT();

	}

	public String getMessageString(String key) {
		return this.extension.getMessageString(key);
	}
	
	/**
	 * Generate alert to report
	 */
	public void generateAlertReport(boolean fullReport) {
		boolean result = false;
		//choose file 
		String filename =extension.getFileName();
		if (!filename.isEmpty()){
			java.util.List<List<Alert>> alerts = new ArrayList<List<Alert>>();
			// generate full report
			if (fullReport){
				java.util.List<Alert> allAlerts = extension.getAllAlerts();
				// sort alerts
				Collections.sort(allAlerts, Collections.reverseOrder()); 
				//join same alerts
				for (int i = 0; i < allAlerts.size(); i++) {
					Alert alertAllAlerts = allAlerts.get(i);
					alerts.add(extension.getAlertsSelected(alertAllAlerts));
					for (int j = 0; j < allAlerts.size(); j++) {
						Alert alertToCompare= allAlerts.get(j);
						if (alertAllAlerts.getAlert().equals(alertToCompare.getAlert())){
							allAlerts.remove(j);
							j = 0;
						}
					}
					i = 0;
				}
				
			} else {
				if (treeAlert.getLastSelectedPathComponent() != null) {
					TreePath[] paths = treeAlert.getSelectionPaths();
					if (paths.length > 0) {
						extension.getAllAlerts();
						for (int i = 0; i < paths.length; i++) {
							TreePath treepath = paths[i];
							DefaultMutableTreeNode alertNode = (DefaultMutableTreeNode) treepath
									.getLastPathComponent();
							if (alertNode != null
									&& alertNode.getUserObject() != null) {
								Object obj = alertNode.getUserObject();
								if (obj instanceof Alert) {
									Alert alert = (Alert) obj;
									if (!checkDuplicateAlert(alerts,alert))
										alerts.add(extension.getAlertsSelected(alert));
								}
							}
						}
					}
				}
			}
			// Generate report
			if (!alerts.isEmpty()) {
				if (extension.getParams().getFormatReport().equals("PDF"))
					result = reportExportPDF.exportAlert(alerts, filename,
							extension);
				else
					result = reportExportODT.exportAlert(alerts,filename,
							extension);
				if (result)
					View.getSingleton().showMessageDialog(
							getMessageString("alert.export.message.export.ok"));
				else
					View.getSingleton().showMessageDialog(
							getMessageString("alert.export.message.export.fail"));
				}
			//clear alertsDB from memory
			extension.clearAlertsDB();
			}

	}
	/**
	 * Check if have a Alert Duplicate select
	 * @param alerts
	 * @param alert
	 * @return
	 */
	private boolean checkDuplicateAlert(java.util.List<List<Alert>> alerts,Alert alert){
		boolean result = false;
		for (int i = 0; i < alerts.size(); i++) {
			java.util.List<Alert> listAlert = alerts.get(i);
			if (listAlert.contains(alert))
				return true;
		}
		return result;
	}
	/**
	 * This method initializes this
	 * 
	 * @return void
	 */
	private void initialize() {

		this.addActionListener(new java.awt.event.ActionListener() {

			public void actionPerformed(java.awt.event.ActionEvent e) {

                generateAlertReport(false);

			}
		});

	}

	public void setExtension(ExtensionAlertReportExport extension) {
		this.extension = extension;
	}

	@Override
	public boolean isEnableForComponent(Component invoker) {
		if (invoker.getName() != null && "treeAlert".equals(invoker.getName())) {
			JTree tree = (JTree) invoker;
			if (tree.getLastSelectedPathComponent() != null) {
				DefaultMutableTreeNode node = (DefaultMutableTreeNode) tree
						.getLastSelectedPathComponent();
				this.treeAlert = tree;
				if (!node.isRoot()) {
					return true;
				}
			}

		}
		return false;
	}

}
