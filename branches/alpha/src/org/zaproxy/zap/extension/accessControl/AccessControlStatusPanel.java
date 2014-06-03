package org.zaproxy.zap.extension.accessControl;

import java.awt.Component;

import javax.swing.ImageIcon;
import javax.swing.JLabel;

import org.apache.log4j.Logger;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.scan.BaseScannerThreadManager;
import org.zaproxy.zap.view.panels.AbstractScanToolbarStatusPanel;

/**
 * Under development...
 */
public class AccessControlStatusPanel extends AbstractScanToolbarStatusPanel {

	private static final long serialVersionUID = 3717381205061196129L;

	private static final Logger log = Logger.getLogger(AccessControlStatusPanel.class);

	private ExtensionAccessControl extension;

	public AccessControlStatusPanel(ExtensionAccessControl extension,
			BaseScannerThreadManager<AccessControlScannerThread> threadManager) {

		super("accessControl", new ImageIcon(
				AccessControlStatusPanel.class.getResource("/resource/icon/16/accessControl.png")),
				threadManager);
		this.extension = extension;
	}

	@Override
	protected Component getWorkPanel() {
		// TODO Auto-generated method stub
		return new JLabel("Results will be displayed here....");
	}

	@Override
	protected Component switchViewForContext(Context context) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	protected void startScan(Context context) {
		log.info("Access Control start on Context: " + context);
		extension.showScanOptionsDialog(context);
	}
}
