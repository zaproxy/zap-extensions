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
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.extension.accessControl.AccessControlScannerThread.AccessControlScanListener;
import org.zaproxy.zap.extension.accessControl.AccessControlScannerThread.AccessControlScanStartOptions;
import org.zaproxy.zap.extension.accessControl.widgets.SiteTreeNode;
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
		VALID(Constant.messages.getString("accessControl.scanResult.valid")), ILLEGAL(Constant.messages
				.getString("accessControl.scanResult.illegal")), UNKNOWN(Constant.messages
				.getString("accessControl.scanResult.unknown"));

		private final String localizedName;

		private AccessControlScanResult(String localizedName) {
			this.localizedName = localizedName;
		}

		@Override
		public String toString() {
			return localizedName;
		}
	};

	private static final Logger log = Logger.getLogger(AccessControlScannerThread.class);

	private List<User> targetUsers;
	private AuthorizationDetectionMethod authorizationDetection;
	/** The HTTP sender used to effectively send the data. */
	private HttpSender httpSender;
	private ContextAccessRulesManager accessRulesManager;
	private List<AccessControlResultEntry> scanResults;

	private ExtensionAccessControl extension;

	public AccessControlScannerThread(int contextId, ExtensionAccessControl extension) {
		super(contextId);
		this.extension = extension;
	}

	@Override
	public void startScan() {
		this.scanResults = new LinkedList<>();
		this.targetUsers = getStartOptions().targetUsers;
		this.accessRulesManager = extension.getContextAccessRulesManager(getStartOptions().targetContext
				.getIndex());
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

			// Convert the SiteNode to a SiteTreNode (for now, before we merge things)
			SiteTreeNode stn = new SiteTreeNode(sn.getNodeName(), originalMessage.getRequestHeader().getURI());

			// For each of the users, attack the node
			for (User user : targetUsers) {
				attackNode(stn, originalMessage, user);
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

	private void attackNode(SiteTreeNode stn, HttpMessage originalMessage, User user) {
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

		// Infer the access rule that should apply for the node and the user, taking into
		// consideration the 'unauthenticated' case
		AccessRule rule = accessRulesManager.inferRule(user != null ? user.getId()
				: ContextAccessRulesManager.UNAUTHENTICATED_USER_ID, stn);

		// Compute the result based on whether the request was authorized and the access rule
		AccessControlScanResult result = AccessControlScanResult.UNKNOWN;
		switch (rule) {
		case ALLOWED:
			result = authorized ? AccessControlScanResult.VALID : AccessControlScanResult.ILLEGAL;
			break;
		case DENIED:
			result = !authorized ? AccessControlScanResult.VALID : AccessControlScanResult.ILLEGAL;
			break;
		default:
			result = AccessControlScanResult.UNKNOWN;
			break;
		}

		// And notify any listeners of the obtained result
		AccessControlResultEntry resultEntry = new AccessControlResultEntry(hRef, user, authorized, result,
				rule);
		notifyScanResultObtained(resultEntry);
		this.scanResults.add(resultEntry);
	}

	private List<SiteNode> getTargetUrlsList() {
		return Model.getSingleton().getSession()
				.getNodesInContextFromSiteTree(getStartOptions().targetContext);
	}

	private void notifyScanResultObtained(AccessControlResultEntry scanResult) {
		for (AccessControlScanListener l : listeners)
			l.scanResultObtained(contextId, scanResult);
	}

	public List<AccessControlResultEntry> getLastScanResults() {
		if (scanResults == null)
			return null;
		return Collections.unmodifiableList(scanResults);
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
		 * @param result the result obtained during the scan. The user contained can be {@code null}
		 *            , for results obtained when scanning as 'un-authenticated'
		 */
		void scanResultObtained(int contextId, AccessControlResultEntry result);
	}

	public static final class AccessControlResultEntry {

		private HistoryReference reference;
		private User user;
		private boolean requestAuthorized;
		private AccessControlScanResult result;
		private AccessRule accessRule;

		public AccessControlResultEntry(HistoryReference historyReference, User user,
				boolean requestAuthorized, AccessControlScanResult result, AccessRule accessRule) {
			this.reference = historyReference;
			this.user = user;
			this.result = result;
			this.requestAuthorized = requestAuthorized;
			this.accessRule = accessRule;
		}

		public HistoryReference getHistoryReference() {
			return reference;
		}

		public Integer getHistoryId() {
			return reference.getHistoryId();
		}

		public String getMethod() {
			return reference.getMethod();
		}

		public String getUri() {
			return reference.getURI().toString();
		}

		public Integer getStatusCode() {
			return reference.getStatusCode();
		}

		public User getUser() {
			return user;
		}

		public AccessControlScanResult getResult() {
			return result;
		}

		public AccessRule getAccessRule() {
			return accessRule;
		}

		public boolean isRequestAuthorized() {
			return requestAuthorized;
		}

	}
}
