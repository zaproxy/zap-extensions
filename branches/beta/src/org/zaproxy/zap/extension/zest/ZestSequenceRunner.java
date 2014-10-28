/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 * 
 * Copyright 2014 The ZAP Development Team
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
package org.zaproxy.zap.extension.zest;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.httpclient.cookie.CookiePolicy;
import org.apache.log4j.Logger;
import org.mozilla.zest.core.v1.ZestActionFailException;
import org.mozilla.zest.core.v1.ZestAssertFailException;
import org.mozilla.zest.core.v1.ZestAssignFailException;
import org.mozilla.zest.core.v1.ZestAssignment;
import org.mozilla.zest.core.v1.ZestClientFailException;
import org.mozilla.zest.core.v1.ZestInvalidCommonTestException;
import org.mozilla.zest.core.v1.ZestRequest;
import org.mozilla.zest.core.v1.ZestResponse;
import org.mozilla.zest.core.v1.ZestScript;
import org.mozilla.zest.core.v1.ZestStatement;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.AbstractPlugin;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.extension.ascan.ExtensionActiveScan;
import org.zaproxy.zap.extension.script.SequenceScript;

public class ZestSequenceRunner extends ZestZapRunner implements SequenceScript {

	private ZestScriptWrapper script = null; 
	private static final Logger logger = Logger.getLogger(ZestSequenceRunner.class);
	private static final Map<String, String> EMPTYPARAMS = new HashMap<String, String>();
	private AbstractPlugin currentPlugin = null;
	private ZestResponse tempLastResponse = null;
	private ExtensionHistory extHistory = null;
	private ExtensionActiveScan extAscan = null;

	/**
	 * Initialize a ZestSequenceRunner.
	 * @param extension The Zest Extension.
	 * @param wrapper A wrapper for the current script.
	 */
	public ZestSequenceRunner(ExtensionZest extension, ZestScriptWrapper wrapper) {
		super(extension, wrapper);
		this.script = wrapper;
		this.setStopOnAssertFail(false);
	}

	@Override
	public List<HttpMessage> getAllRequestsInScript() {
		ArrayList<HttpMessage> requests = new ArrayList<HttpMessage>();

		for(ZestStatement stmt : this.script.getZestScript().getStatements()) {
			try {
				if(stmt.getElementType().equals("ZestRequest")) {
					ZestRequest req = (ZestRequest)stmt;
					HttpMessage scrMessage = ZestZapUtils.toHttpMessage(req, req.getResponse());
					requests.add(scrMessage);
				}
			}catch(Exception e) {
				logger.debug("Exception occurred while fetching HttpMessages from sequence script: " + e.getMessage());
			}
		}
		return requests;
	}

	@Override
	public HttpMessage runSequenceBefore(HttpMessage msg, AbstractPlugin plugin) {
		HttpMessage msgOriginal = msg.cloneAll();

		this.currentPlugin = plugin;
		try	{
			//Get the subscript for the message to be scanned, and run it. The subscript will contain all
			//prior statements in the script. 
			HttpMessage msgScript = getMatchingMessageFromScript(msg);
			ZestScript scr = getBeforeSubScript(msgScript);
			HttpSender sender = this.currentPlugin.getParent().getHttpSender();
			sender.getClient().getParams().setCookiePolicy(CookiePolicy.BROWSER_COMPATIBILITY);
			sender.getClient().getState().clearCookies();
			this.setHttpClient(sender.getClient());
			this.run(scr, EMPTYPARAMS);

			//Once the script has run, update the message with results from 
			mergeRequestBodyFromScript(msgOriginal);
			String reqBody = msgOriginal.getRequestBody().toString();
			reqBody = java.net.URLDecoder.decode(reqBody, "UTF-8");
			reqBody = this.replaceVariablesInString(reqBody, false);
			msgOriginal.setRequestBody(reqBody);
			msgOriginal.getRequestHeader().setContentLength(msgOriginal.getRequestBody().length());
		}
		catch(Exception e) {
			logger.debug("Error running Sequence script in 'runSequenceBefore' method : " + e.getMessage());
		}
		return msgOriginal;
	}

	private void mergeRequestBodyFromScript(HttpMessage msg)
	{
		HttpMessage scrMsg = getMatchingMessageFromScript(msg);

		if(scrMsg != null) {
			String reqBodyFromScript = scrMsg.getRequestBody().toString();
			if(reqBodyFromScript == null || reqBodyFromScript == "") {
				return;
			}
			String[] nameValuePairs = reqBodyFromScript.split("&");

			for(String pair : nameValuePairs) {
				String[] entry = pair.split("=");
				if(entry[1].startsWith("{{") && entry[1].endsWith("}}")) {
					String reqBodyFromOriginal = msg.getRequestBody().toString();
					if(reqBodyFromOriginal.contains(entry[0])) {
						String mergedRequestBody = "";
						String[] originalPairs = reqBodyFromOriginal.split("&");
						for(int i = 0; i < originalPairs.length; i++) {
							String originalPair = originalPairs[i];
							String[] originalEntry = originalPair.split("=");
							if(originalEntry[0].equals(entry[0])) {
								originalEntry[1] = entry[1];
							}
							mergedRequestBody += originalEntry[0] + "=" + originalEntry[1];
							if(i < (originalPairs.length - 1)) {
								mergedRequestBody += "&";
							}
						}
						msg.setRequestBody(mergedRequestBody);
					}
				}
			}
		}
	}

	@Override
	public void runSequenceAfter(HttpMessage msg, AbstractPlugin plugin) {		

		try {
			this.tempLastResponse = ZestZapUtils.toZestResponse(msg);
		} catch (Exception e) {
			// Ignore - probably initial request, and therefore no "last response" available.
		}

		this.currentPlugin = plugin;
		try	{
			HttpMessage msgScript = getMatchingMessageFromScript(msg);
			ZestScript scr = getAfterSubScript(msgScript);

			HttpSender sender = this.currentPlugin.getParent().getHttpSender();
			this.setHttpClient(sender.getClient());
			this.run(scr, EMPTYPARAMS);

			//Clean up redundant cookies
			sender.getClient().getState().clearCookies();		
		} catch (Exception e){
			logger.debug("Error running Sequence script in 'runSequenceAfter' method : " + e.getMessage());
		}
	}

	@Override
	public boolean isPartOfSequence(HttpMessage msg) {
		for(ZestStatement stmt : script.getZestScript().getStatements()) {
			if(isSameRequest(msg, stmt)) {
				return true;
			}
		}
		return false;
	}	

	@Override
	public ZestResponse runStatement(ZestScript script, ZestStatement stmt,
			ZestResponse lastResponse) throws ZestAssertFailException,
			ZestActionFailException, ZestInvalidCommonTestException,
			IOException, ZestAssignFailException, ZestClientFailException {

		//This method makes sure each request from a Sequence Script is displayed on the Active Scan results tab.
		ZestResponse response = null;
		try {
			response = super.runStatement(script, stmt, lastResponse);
		}catch(NullPointerException e) {
			logger.debug("NullPointerException occurred, while running Sequence Script: " + e.getMessage());
		}

		try {
			if(stmt.getElementType().equals("ZestRequest"))	{
				ZestRequest req = (ZestRequest)stmt;
				HttpMessage msg = ZestZapUtils.toHttpMessage(req, response);

				String reqBody = msg.getRequestBody().toString();
				reqBody = this.replaceVariablesInString(reqBody, false);
				msg.setRequestBody(reqBody);
				msg.setTimeSentMillis(System.currentTimeMillis());
				msg.setTimeElapsedMillis((int) response.getResponseTimeInMs());
				this.currentPlugin.getParent().notifyNewMessage(msg);
			}
		}
		catch(Exception e) {
			logger.debug("Exception while trying to notify of unscanned message in a sequence.");
		}
		return response;
	}

	@Override
	public String handleAssignment(ZestScript script, ZestAssignment assign,
			ZestResponse lastResponse) throws ZestAssignFailException {
		if(lastResponse == null)
		{
			lastResponse = this.tempLastResponse;
			this.tempLastResponse = null;
		}
		return super.handleAssignment(script, assign, lastResponse);
	}

	private boolean isSameRequest(HttpMessage msg, ZestStatement stmt) {
		try {
			if(stmt.getElementType().equals("ZestRequest")) {
				//				ZestParam param = new ZestParam();
				//				param.setIncludeResponses(true);
				//				ZestRequest msgzest = ZestZapUtils.toZestRequest(msg, true, param);
				ZestRequest msgzest = ZestZapUtils.toZestRequest(msg, true, new ZestParam());
				ZestRequest req = (ZestRequest)stmt;

				if(msgzest.getUrl().equals(req.getUrl())) {
					if(msgzest.getMethod().equals(req.getMethod())) {
						return true;
					}
				}
			}
		}
		catch(Exception e) {
			logger.debug("Exception in ZestSequenceRunner isSameRequest:" + e.getMessage());
		}
		return false;
	}

	private HttpMessage getMatchingMessageFromScript(HttpMessage msg) {
		try {
			for(ZestStatement stmt : this.script.getZestScript().getStatements()) {
				if(isSameRequest(msg, stmt)) {
					ZestRequest req = (ZestRequest)stmt;
					return ZestZapUtils.toHttpMessage(req, req.getResponse());
				}
			}
		}
		catch(Exception e) {
			logger.debug("Exception in getMatchingMessageFromScript: " + e.getMessage());
		}
		return null;
	}

	//Gets a script containing all statements prior to the supplied HttpMessage.
	private ZestScript getBeforeSubScript(HttpMessage msg) {
		ZestScript scr = new ZestScript();
		ArrayList<ZestStatement> stmts = new ArrayList<ZestStatement>();

		for(ZestStatement stmt : this.script.getZestScript().getStatements()) {
			if(isSameRequest(msg, stmt)) {
				break;
			}
			stmts.add(stmt);
		}
		scr.setStatements(stmts);
		return scr;
	}

	//Gets a script containing all statements after the supplied HttpMessage.
	private ZestScript getAfterSubScript(HttpMessage msg) {
		ZestScript scr = new ZestScript();
		ArrayList<ZestStatement> stmts = new ArrayList<ZestStatement>();
		boolean foundMatch = false;
		for(ZestStatement stmt : this.script.getZestScript().getStatements()) {
			if(!foundMatch && isSameRequest(msg, stmt)){
				foundMatch = true;
				continue;
			}

			if(foundMatch){
				stmts.add(stmt);
			}
		}
		scr.setStatements(stmts);
		return scr;
	}

	@Override
	public void scanSequence() {
		SiteNode fakeRoot = new SiteNode(null, 11, "");
		SiteNode fakeDirectory = new SiteNode(null, 11, "");

		for(ZestStatement stmt : script.getZestScript().getStatements()) {
			try {
				if(stmt.getElementType().equals("ZestRequest")) {
					ZestRequest req = (ZestRequest)stmt;
					HttpMessage msg = ZestZapUtils.toHttpMessage(req, req.getResponse());
					SiteNode node = messageToSiteNode(msg);

					if(node != null) {
						fakeDirectory.add(node);
					}
				}
			}
			catch(Exception e) {
				logger.info("An exception occurred while scanning sequence directly: " + e.getMessage(), e);
			}
		}
		fakeRoot.add(fakeDirectory);
		getActiveScanner().startScan(fakeRoot);
	}

	private SiteNode messageToSiteNode(HttpMessage msg)
	{
		SiteNode temp = null;
		try {
			temp = new SiteNode(null, 11, "");
			HistoryReference ref = new HistoryReference(getHistory().getModel().getSession(), HistoryReference.TYPE_RESERVED_11, msg);
			getHistory().addHistory(ref);
			temp.setHistoryReference(ref);
		} catch(Exception e) {
			logger.info("An exception occurred while converting a HttpMessage to SiteNode: " + e.getMessage(), e);
		}
		return temp;
	}

	private ExtensionHistory getHistory() {
		if(extHistory == null) {
			extHistory = (ExtensionHistory) Control.getSingleton().getExtensionLoader().getExtension(ExtensionHistory.class);
		}
		return extHistory;
	}

	private ExtensionActiveScan getActiveScanner() {
		if(extAscan == null) {
			extAscan = (ExtensionActiveScan) Control.getSingleton().getExtensionLoader().getExtension(ExtensionActiveScan.class);
		}
		return extAscan;
	}
}