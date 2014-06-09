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
