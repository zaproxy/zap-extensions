package org.zaproxy.zap.extension.alertReport;

import java.awt.Component;
import java.util.ArrayList;
import java.util.List;
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
	 * This method initializes this
	 * 
	 * @return void
	 */
	private void initialize() {
		 // Load extension specific language files - these are held in the extension jar
        messages = ResourceBundle.getBundle(
        		this.getClass().getPackage().getName() + ".Messages", Constant.getLocale());
		
		this.setText(this.getMessageString("alert.export.message.menuitem"));

		this.addActionListener(new java.awt.event.ActionListener() {

			public void actionPerformed(java.awt.event.ActionEvent e) {
				// change visibility of AlertPanel and TreeAlert
				extAlert = (ExtensionAlert) Control.getSingleton()
						.getExtensionLoader().getExtension("ExtensionAlert");
				
				
				if (treeAlert.getLastSelectedPathComponent() != null) {
					TreePath[] paths = treeAlert.getSelectionPaths();
					List alerts = new ArrayList();
					if (paths.length>0){
						for (int i = 0; i < paths.length; i++) {
							TreePath treepath = (TreePath) paths[i];
							DefaultMutableTreeNode alertNode = (DefaultMutableTreeNode) treepath.getLastPathComponent();
							if (alertNode != null && alertNode.getUserObject() != null) {
								Object obj = alertNode.getUserObject();
								if (obj instanceof Alert) {
									Alert alert = (Alert) obj;
									alerts.add(extension.getAlertsSelected(alert));
								}
							}
						}
						// Generate report
						if (!alerts.isEmpty()) {
							if (reportExportPDF.exportAlertPDF(alerts,
									extension.getFileName(),extension))
								View.getSingleton()
										.showMessageDialog(
												getMessageString("alert.export.message.export.ok"));
							else
								View.getSingleton()
										.showMessageDialog(
												getMessageString("alert.export.message.export.fail"));
							}
						}
						
						}
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
