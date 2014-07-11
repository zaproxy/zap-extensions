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

import java.io.IOException;
import java.sql.SQLException;
import java.util.LinkedList;
import java.util.List;

import org.apache.log4j.Logger;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
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

	public enum AccessControlScanResult {
		VALID, ILLEGAL, UNKNOWN
	};

	private static final Logger log = Logger.getLogger(AccessControlScannerThread.class);

	private List<User> targetUsers;
	private AuthorizationDetectionMethod authorizationDetection;
	/** The HTTP sender used to effectively send the data. */
	private HttpSender httpSender;

	public AccessControlScannerThread(int contextId) {
		super(contextId);
	}

	@Override
	public void startScan() {
		this.targetUsers = getStartOptions().targetUsers;
		this.authorizationDetection = getStartOptions().targetContext.getAuthorizationDetectionMethod();
		// Initialize the HTTP sender
		this.httpSender = new HttpSender(Model.getSingleton().getOptionsParam().getConnectionParam(), true,
				HttpSender.ACCESS_CONTROL_SCANNER_INITIATOR);
		// Do not follow redirections because we want to check the initial response
		httpSender.setFollowRedirect(false);

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

		// For each of the users, attack each of the nodes in the context
		// NOTE: In order to minimize the number of database reads for the 'original' message, cycle
		// through the messages first and then through the users
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

			// Check whether we should attack the node
			if (!shouldAttackNode(originalMessage))
				continue;

			// For each of the users, attack the node
			for (User user : targetUsers) {
				attackNode(sn, originalMessage, user);

			}
			// Make sure we update the progress
			setScanProgress(++progress);
		}

		// Setup the finished status properly
		log.debug("Access control scan finished.");
		setScanProgress(getScanMaximumProgress());
		setRunningState(false);
		notifyScanFinished();
	}

	/**
	 * Check whether we should attack the node.
	 */
	private boolean shouldAttackNode(HttpMessage originalMessage) {
		// Do not attack nodes which don't have a response as they might correspond to places in the
		// application not accessible via exploration (they are probably folders)
		return originalMessage != null && !originalMessage.getResponseHeader().isEmpty();
	}

	private void attackNode(SiteNode sn, HttpMessage originalMessage, User user) {
		log.info("" + user);
		if (log.isDebugEnabled())
			log.debug("Attacking node: '" + originalMessage.getRequestHeader().getURI() + "' as user: "
					+ (user != null ? user.getName() : "unauthenticated"));
		// Clone the original message and send it from the point of view of the user
		HttpMessage scanMessage = originalMessage.cloneRequest();
		scanMessage.setRequestingUser(user);

		try {
			httpSender.sendAndReceive(scanMessage);
		} catch (IOException e) {
			log.error("Error occurred while sending/receiving access control testing message to:"
					+ scanMessage.getRequestHeader().getURI(), e);
			return;
		}

		// Analyze the message and check if the access control rules are matched
		boolean authorized = !authorizationDetection.isResponseForUnauthorizedRequest(scanMessage);

		// Save the message in a history reference
		HistoryReference hRef;
		try {
			hRef = new HistoryReference(Model.getSingleton().getSession(),
					HistoryReference.TYPE_ACCESS_CONTROL, scanMessage);
		} catch (HttpMalformedHeaderException | SQLException e) {
			log.error(
					"An error has occurred while saving AccessControl testing message in HistoryReference: "
							+ e.getMessage(), e);
			return;
		}

		// And notify any listeners of the obtained result
		notifyScanResultObtained(hRef, user, authorized, AccessControlScanResult.UNKNOWN, AccessRule.UNKNOWN);
	}

	private List<SiteNode> getTargetUrlsList() {
		return Model.getSingleton().getSession()
				.getNodesInContextFromSiteTree(getStartOptions().targetContext);
	}

	private void notifyScanResultObtained(HistoryReference msg, User user, boolean requestAuthorized,
			AccessControlScanResult result, AccessRule accessRule) {
		for (AccessControlScanListener l : listeners)
			l.scanResultObtained(contextId, msg, user, requestAuthorized, result, accessRule);
	}

	/**
	 * The scan options for the {@link AccessControlScannerThread} performing access control
	 * testing.
	 */
	public static class AccessControlScanStartOptions implements ScanStartOptions {
		public Context targetContext;
		public List<User> targetUsers;

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
		 * @param user the user for which the result was obtained. Can be {@code null}, for results
		 *            obtained for scanning as 'un-authenticated'
		 */
		void scanResultObtained(int contextId, HistoryReference historyReference, User user,
				boolean requestAuthorized, AccessControlScanResult result, AccessRule accessRule);
	}
}
