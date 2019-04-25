/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 * 
 * Copyright 2017 The ZAP Development Team
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

package org.zaproxy.zap.extension.pscanrulesBeta;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import net.htmlparser.jericho.Source;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;
import org.zaproxy.zap.extension.users.ExtensionUserManagement;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.users.User;

public class UsernameIdorScanner extends PluginPassiveScanner {

	private static final String MESSAGE_PREFIX = "pscanbeta.usernameidor.";
	private static final int PLUGIN_ID = 10057;

	private PassiveScanThread parent = null;
	private static final Logger LOGGER = Logger.getLogger(UsernameIdorScanner.class);

	private List<User> testUsers = null;

	private ExtensionUserManagement extUserMgmt;

	@Override
	public void setParent(PassiveScanThread parent) {
		this.parent = parent;
	}

	private List<User> getUsers() {
		if (testUsers != null) {
			return testUsers;
		}
		
		if (getExtensionUserManagement() == null) {
			return Collections.emptyList();
		}

		List<User> usersList = new ArrayList<>();

		for (Context context : Model.getSingleton().getSession().getContexts()) {
			usersList.addAll(extUserMgmt.getContextUserAuthManager(context.getIndex()).getUsers());
		}
		return usersList;
	}

	@Override
	public void scanHttpRequestSend(HttpMessage msg, int id) {
		// Only checking the response for this plugin
	}

	@Override
	public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
		List<User> scanUsers = getUsers();
		if (scanUsers.isEmpty()) {// Should continue if not empty
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("There does not appear to be any contexts with configured users.");
			}
			return;
		}

		long start = System.currentTimeMillis();

		String response = msg.getResponseHeader().toString() + msg.getResponseBody().toString();
		String username;

		for (User user : scanUsers) {
			username = user.getName();
			Map<String, String> hashes = new HashMap<String, String>();
			hashes.put("MD2", DigestUtils.md2Hex(username));
			hashes.put("MD5", DigestUtils.md5Hex(username));
			hashes.put("SHA1", DigestUtils.sha1Hex(username));
			hashes.put("SHA256", DigestUtils.sha256Hex(username));
			hashes.put("SHA384", DigestUtils.sha384Hex(username));
			hashes.put("SHA512", DigestUtils.sha512Hex(username));
			for (Map.Entry<String, String> entry : hashes.entrySet()) {
				String hash = entry.getValue();
				String evidence = match(response, Pattern.compile(hash, Pattern.CASE_INSENSITIVE));
				if (evidence != null) {
					this.raiseAlert(username, evidence, entry.getKey(), id, msg);
				}
			}
		}
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug("\tScan of record " + id + " took " + (System.currentTimeMillis() - start) + " ms");
		}
	}

	private void raiseAlert(String username, String evidence, String hashType, int id, HttpMessage msg) {
		Alert alert = new Alert(getPluginId(), Alert.RISK_INFO, Alert.CONFIDENCE_HIGH, // PluginID, Risk, Reliability
				getName());
		alert.setDetail(getDescription(username), // Description
				msg.getRequestHeader().getURI().toString(), // URI
				"", // Param
				"", // Attack
				getOtherinfo(hashType, evidence), // Other info
				getSolution(), // Solution
				getReference(), // References
				evidence, // Evidence
				284, // CWE-284: Improper Access Control
				02, // WASC-02: Insufficient Authorization
				msg); // HttpMessage
		parent.raiseAlert(id, alert);
	}

	@Override
	public int getPluginId() {
		return PLUGIN_ID;
	}

	@Override
	public String getName() {
		return Constant.messages.getString(MESSAGE_PREFIX + "name");
	}

	private String getDescription(String username) {
		return Constant.messages.getString(MESSAGE_PREFIX + "desc", username);
	}

	private String getSolution() {
		return Constant.messages.getString(MESSAGE_PREFIX + "soln");
	}

	private String getReference() {
		return Constant.messages.getString(MESSAGE_PREFIX + "refs");
	}

	private String getOtherinfo(String hashType, String hashValue) {
		return Constant.messages.getString(MESSAGE_PREFIX + "otherinfo", hashType, hashValue);
	}

	public String match(String contents, Pattern pattern) {
		Matcher matcher = pattern.matcher(contents);
		if (matcher.find()) {
			return matcher.group();
		}
		return null;
	}

	// The following methods support unit testing
	protected void setUsers(String username) {
		testUsers = new ArrayList<User>();
		this.testUsers.add(new User(testUsers.size() + 1, username));
	}

	protected ExtensionUserManagement getExtensionUserManagement() {
		if (extUserMgmt == null) {
			extUserMgmt = Control.getSingleton().getExtensionLoader().getExtension(ExtensionUserManagement.class);
		}
		return extUserMgmt;
	}

	protected void setExtensionUserManagement(ExtensionUserManagement extensionUserManagement) {
		this.extUserMgmt = extensionUserManagement;
	}

}
