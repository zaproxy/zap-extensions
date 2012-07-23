package org.zaproxy.zap.extension.report;

import java.awt.Component;
import java.util.List;
import java.util.ResourceBundle;

import javax.swing.JTree;
import javax.swing.tree.DefaultMutableTreeNode;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.extension.ExtensionPopupMenuItem;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.alert.ExtensionAlert;

public class ReportExportMenuItem extends ExtensionPopupMenuItem {

	private static final long serialVersionUID = 1L;
	private ExtensionReportExport extension = null;
	private ExtensionAlert extAlert = null;
	private ReportExportPDF reportExportPDF = null;
	private JTree treeAlert = null;
	private ResourceBundle messages = null;

	/**
	 * @param label
	 */
	public ReportExportMenuItem(String label) {
		super(label);
		initialize();
		if (this.reportExportPDF == null)
			this.reportExportPDF = new ReportExportPDF();
	
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
					DefaultMutableTreeNode node = (DefaultMutableTreeNode) treeAlert.getLastSelectedPathComponent();
					if (node != null && node.getUserObject() != null) {
						Object obj = node.getUserObject();
						if (obj instanceof Alert) {
							Alert alert = (Alert) obj;
	
							List<Alert> alerts = extension.getAlertsSelected(alert);
							if (alerts != null) {
								if (reportExportPDF.exportAlertPDF(alerts,
										extension.getFileName(alert),extension))
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
				}
		});

	}

	public void setExtension(ExtensionReportExport extension) {
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
