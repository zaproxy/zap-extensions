package org.zaproxy.zap.extension.alertReport;

import java.awt.Component;
import java.util.ArrayList;
import java.util.Collections;
import java.util.ResourceBundle;

import javax.swing.JTree;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.TreePath;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.extension.ExtensionPopupMenuItem;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.alert.ExtensionAlert;

public class AlertReportExportMenuItem extends ExtensionPopupMenuItem {

	private static final long serialVersionUID = 1L;
	private ExtensionAlertReportExport extension = null;
	private ExtensionAlert extAlert = null;
	private AlertReportExportPDF reportExportPDF = null;
	private AlertReportExportODT reportExportODT = null;
	private JTree treeAlert = null;
	private ResourceBundle messages = null;

	/**
	 * @param label
	 */
	public AlertReportExportMenuItem(String label) {
		super(label);
		initialize();
		if (this.reportExportPDF == null)
			this.reportExportPDF = new AlertReportExportPDF();
		if (this.reportExportODT == null)
			this.reportExportODT = new AlertReportExportODT();

	}

	public String getMessageString(String key) {
		return messages.getString(key);
	}

	public ExtensionAlert getExtAlert() {
		return extAlert;
	}

	public void setExtAlert(ExtensionAlert extAlert) {
		this.extAlert = extAlert;
	}
	
	/**
	 * Generate alert to report
	 */
	public void generateAlertReport(boolean fullReport) {
		java.util.List alerts = new ArrayList();
		// generate full report
		if (fullReport){
			extAlert = (ExtensionAlert) Control.getSingleton()
					.getExtensionLoader().getExtension("ExtensionAlert");
			java.util.List<Alert> allAlerts = extAlert.getAllAlerts();
			// sort alerts
			Collections.sort(allAlerts, Collections.reverseOrder()); 
			//join same alerts
			for (int i = 0; i < allAlerts.size(); i++) {
				Alert alertAllAlerts = (Alert) allAlerts.get(i);
				alerts.add(extension.getAlertsSelected(alertAllAlerts));
				for (int j = 0; j < allAlerts.size(); j++) {
					Alert alertToCompare= (Alert) allAlerts.get(j);
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
					for (int i = 0; i < paths.length; i++) {
						TreePath treepath = (TreePath) paths[i];
						DefaultMutableTreeNode alertNode = (DefaultMutableTreeNode) treepath
								.getLastPathComponent();
						if (alertNode != null
								&& alertNode.getUserObject() != null) {
							Object obj = alertNode.getUserObject();
							if (obj instanceof Alert) {
								Alert alert = (Alert) obj;
								alerts.add(extension.getAlertsSelected(alert));
							}
						}
					}
				}
			}
		}
		// Generate report
		if (!alerts.isEmpty()) {
			boolean result = false;
			if (extension.getParams().getFormatReport().equals("PDF"))
				result = reportExportPDF.exportAlert(alerts, extension.getFileName(),
						extension);
			else
				result = reportExportODT.exportAlert(alerts, extension.getFileName(),
						extension);
			if (result)
				View.getSingleton().showMessageDialog(
						getMessageString("alert.export.message.export.ok"));
			else
				View.getSingleton().showMessageDialog(
						getMessageString("alert.export.message.export.fail"));

		}

	}

	/**
	 * This method initializes this
	 * 
	 * @return void
	 */
	private void initialize() {
		// Load extension specific language files - these are held in the
		// extension jar
		messages = ResourceBundle.getBundle(this.getClass().getPackage()
				.getName()
				+ ".Messages", Constant.getLocale());

		this.setText(this.getMessageString("alert.export.message.menuitem"));

		this.addActionListener(new java.awt.event.ActionListener() {

			public void actionPerformed(java.awt.event.ActionEvent e) {
				extAlert = (ExtensionAlert) Control.getSingleton()
						.getExtensionLoader().getExtension("ExtensionAlert");
                generateAlertReport(false);

			}
		});

	}

	public void setExtension(ExtensionAlertReportExport extension) {
		this.extension = extension;
	}

	@Override
	public boolean isEnableForComponent(Component invoker) {
		if (invoker.getName() != null && invoker.getName().equals("treeAlert")) {
			try {
				JTree tree = (JTree) invoker;
				if (tree.getLastSelectedPathComponent() != null) {
					DefaultMutableTreeNode node = (DefaultMutableTreeNode) tree
							.getLastSelectedPathComponent();
					this.treeAlert = tree;
					if (!node.isRoot()) {
						return true;
					}
				}
			} catch (Exception e) {
			}

		}
		return false;
	}

}
