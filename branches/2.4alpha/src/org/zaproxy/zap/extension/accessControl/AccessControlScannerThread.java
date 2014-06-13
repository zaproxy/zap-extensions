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

import java.util.LinkedList;
import java.util.List;

import org.apache.log4j.Logger;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.accessControl.AccessControlScannerThread.AccessControlScanListener;
import org.zaproxy.zap.extension.accessControl.AccessControlScannerThread.AccessControlScanStartOptions;
import org.zaproxy.zap.extension.authorization.AuthorizationDetectionMethod;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.scan.BaseContextScannerThread;
import org.zaproxy.zap.scan.ScanListener;
import org.zaproxy.zap.scan.ScanStartOptions;
import org.zaproxy.zap.users.User;

/**
 * The scanner thread used to test access control issues. Requires
 * {@link AccessControlScanStartOptions} for specifying the scan options.
 * 
 * @see ExtensionAccessControl
 * @see AccessControlScanStartOptions
 */
public class AccessControlScannerThread extends
		BaseContextScannerThread<AccessControlScanStartOptions, AccessControlScanListener> {

	private static final Logger log = Logger.getLogger(AccessControlScannerThread.class);

	private List<User> targetUsers;
	private AuthorizationDetectionMethod authorizationDetection;

	public AccessControlScannerThread(int contextId) {
		super(contextId);
	}

	@Override
	public void startScan() {
		this.targetUsers = getStartOptions().targetUsers;
		this.authorizationDetection = getStartOptions().targetContext.getAuthorizationDetectionMethod();

		super.startScan();
	}

	@Override
	protected void scan() {

		notifyScanStarted();

		// Build the list of urls' which will be attacked
		List<SiteNode> targetNodes = getTargetUrlsList();

		// And set up the state accordingly
		this.setScanMaximumProgress(targetNodes.size() + 1);
		log.debug(String.format("Starting Access Control scan for %d URLs and %d users", targetNodes.size(),
				targetUsers.size()));

		int progress = 0;
		for (SiteNode sn : targetNodes) {
			// Check if it's paused
			checkPausedAndWait();

			// Check if it's stopped
			if (!isRunning())
				break;

			// Actually do the attack
			HttpMessage originalMessage = null;
			try {
				originalMessage = sn.getHistoryReference().getHttpMessage();
			} catch (Exception ex) {
				log.error("An error has occurred while loading history reference message:" + ex.getMessage(),
						ex);
			}
			if (originalMessage != null)
				attackNode(sn, originalMessage);

			// Make sure we update the progress
			setScanProgress(++progress);
		}

		log.debug("Access control scan finished.");
		setScanProgress(getScanMaximumProgress());
		setRunningState(false);
		notifyScanFinished();
	}

	private void attackNode(SiteNode sn, HttpMessage originalMessage) {
		log.debug("Attacking node: " + originalMessage.getRequestHeader().getURI());
		for (User user : targetUsers) {
			notifyScanResultObtained(originalMessage, user, "OK", "Should access");
		}

	}

	private List<SiteNode> getTargetUrlsList() {
		return Model.getSingleton().getSession()
				.getNodesInContextFromSiteTree(getStartOptions().targetContext);
	}

	private void notifyScanResultObtained(HttpMessage msg, User user, String result, String accessRule) {
		for (AccessControlScanListener l : listeners)
			l.scanResultObtained(contextId, msg, user, result, accessRule);
	}

	/**
	 * The scan options for the {@link AccessControlScannerThread} performing access control
	 * testing.
	 */
	public static class AccessControlScanStartOptions implements ScanStartOptions {
		protected Context targetContext;
		protected List<User> targetUsers;

		public AccessControlScanStartOptions() {
			super();
			this.targetUsers = new LinkedList<User>();
		}

	}

	public interface AccessControlScanListener extends ScanListener {

		/**
		 * Callback method called when a scan result has been obtained.
		 *
		 * @param contextId the context id
		 */
		void scanResultObtained(int contextId, HttpMessage msg, User user, String result, String accessRule);
	}
}
