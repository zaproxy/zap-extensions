/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2015 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.zest;

import org.apache.log4j.Logger;
import org.mozilla.zest.core.v1.ZestActionFailException;
import org.mozilla.zest.core.v1.ZestAssertFailException;
import org.mozilla.zest.core.v1.ZestAssertion;
import org.mozilla.zest.core.v1.ZestAssignFailException;
import org.mozilla.zest.core.v1.ZestClientFailException;
import org.mozilla.zest.core.v1.ZestInvalidCommonTestException;
import org.mozilla.zest.core.v1.ZestRequest;
import org.mozilla.zest.core.v1.ZestScript;
import org.mozilla.zest.core.v1.ZestStatement;
import org.parosproxy.paros.core.scanner.AbstractPlugin;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.extension.script.SequenceScript;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ZestIndexBasedSequenceRunner extends ZestZapRunner implements SequenceScript {

	private ExtensionZest extension;
	private ZestScriptWrapper script = null;
	private int indexOfMessage;
	private static final Map<String, String> EMPTY_PARAMS = new HashMap<String, String>();
	private static final Logger logger = Logger.getLogger(ZestSequenceRunner.class);

	public ZestIndexBasedSequenceRunner(ExtensionZest extension, ZestScriptWrapper wrapper, int indexOfMessage) {
		super(extension, wrapper);
		this.extension = extension;
		this.script = wrapper;
		this.indexOfMessage = indexOfMessage;
		this.setHttpClient(new ZestHttpSender(extension.getParam()));
		this.setStopOnAssertFail(false);
	}

	public ZestIndexBasedSequenceRunner(ExtensionZest extension, ZestScriptWrapper wrapper, int indexOfMessage, HttpSender httpSender) {
		super(extension, wrapper);
		this.extension = extension;
		this.script = wrapper;
		this.indexOfMessage = indexOfMessage;
		this.setHttpClient(new ZestHttpSender(httpSender, extension.getParam()));
		this.setStopOnAssertFail(false);
	}

	@Override
	public void scanSequence() {

	}

	@Override
	public HttpMessage runSequenceBefore(HttpMessage httpMessage, AbstractPlugin abstractPlugin) {
		HttpMessage msgOriginal = httpMessage.cloneAll();
		try	{

			//Get the subscript for the message to be scanned, and run it. The subscript will contain all
			//prior statements in the script.
			ZestScript script = getBeforeSubScript();
			this.run(script, EMPTY_PARAMS);

			replaceVariablesInHttpMessage(msgOriginal);
		}
		catch(Exception e) {
			logger.error("Error running Sequence script in 'runSequenceBefore' method : " + e.getMessage());
		}
		return msgOriginal;
	}

	private void replaceVariablesInHttpMessage(HttpMessage msgOriginal) throws HttpMalformedHeaderException, UnsupportedEncodingException {
		String reqHeader = createRequestHeader(msgOriginal);
		String reqBody = msgOriginal.getRequestBody().toString();

		reqHeader = this.replaceVariablesInString(reqHeader, false);
		reqBody = this.replaceVariablesInString(reqBody, false);

		msgOriginal.setRequestHeader(reqHeader);
		msgOriginal.setRequestBody(reqBody);
		msgOriginal.getRequestHeader().setContentLength(msgOriginal.getRequestBody().length());
	}

	private String createRequestHeader(HttpMessage msgOriginal) throws UnsupportedEncodingException {

		String decodedUri = getUrlDecodedUri(msgOriginal);
		String reqHeader = msgOriginal.getRequestHeader().getMethod() + " " + decodedUri + " " + msgOriginal.getRequestHeader().getVersion();
		if(msgOriginal.getRequestHeader().getHeaders().size() > 0){
			reqHeader += "\r\n";
		}

		reqHeader += msgOriginal.getRequestHeader().getHeadersAsString();
		return reqHeader;
	}

	private String getUrlDecodedUri(HttpMessage msgOriginal) throws UnsupportedEncodingException {
		String uri = msgOriginal.getRequestHeader().getURI().toString();
		String decodedUri = uri;
		try {
			decodedUri = URLDecoder.decode(uri, "UTF8");
		}catch (UnsupportedEncodingException e){
			logger.warn("Error URLDecoder.decode: " + e.getMessage());
			throw e;
		}
		return decodedUri;
	}

	@Override
	public void runSequenceAfter(HttpMessage httpMessage, AbstractPlugin abstractPlugin) {
		try {
			Map<String, String> currentVariables = getCurrentVariables();
			ZestRequest zestRequest = handleHttpMessageAsIfItWasExecutedByZest(httpMessage, currentVariables);

			ZestScript scr = getAfterSubScript();

			//Send current Variables to next script  as inputParams
			this.run(scr, zestRequest, currentVariables);

		} catch(Exception e) {
			logger.error("Error running Sequence script in 'runSequenceAfter' method : " + e.getMessage());
		}
	}

	private Map<String, String> getCurrentVariables() {
		Map<String, String> currentVariables = new HashMap<String, String>();
		for (String[] keyValue : this.getVariables()) {
            currentVariables.put(keyValue[0], keyValue[1]);
        }
		return currentVariables;
	}

	private ZestRequest handleHttpMessageAsIfItWasExecutedByZest(HttpMessage httpMessage, Map<String, String> currentVariables) throws IOException, SQLException, ZestAssertFailException, ZestActionFailException, ZestAssignFailException, ZestClientFailException, ZestInvalidCommonTestException {
		ZestRequest zestRequest = ZestZapUtils.toZestRequest(httpMessage, false, true, extension.getParam());

		//Add the ZestAssertions, because a converted ZestRequest has no assertions!
		ZestRequest origZestRequest = getRequest();
		for (ZestAssertion zestAssertion : origZestRequest.getAssertions()) {
			zestRequest.addAssertion(zestAssertion);
		}

		// current runtime does not provide lasResponse/lastRequest and variables because http request
		// was not executed here! Set ZestRuntime into state as if it executes the Request by itself!
		ZestScript emptyZestScript = new ZestScript();
		this.run(emptyZestScript, zestRequest, currentVariables);
		this.setStandardVariables(zestRequest);
		this.setStandardVariables( zestRequest.getResponse());

		//Display the HttpMessage in ZestRequestsTab, though it runs i.e. in the Fuzzer
		handleResponse(zestRequest, zestRequest.getResponse());
		return zestRequest;
	}

	@Override
	public boolean isPartOfSequence(HttpMessage httpMessage) {
		return false;
	}

	@Override
	public List<HttpMessage> getAllRequestsInScript() {
		ArrayList<HttpMessage> requests = new ArrayList<>();

		for(ZestStatement stmt : this.script.getZestScript().getStatements()) {
			try {
				if(stmt instanceof ZestRequest) {
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

	private int getZestStatementIndex() {
		int currentZestRequestIndex = 0;
		List<ZestStatement> statements = getAllStatements();
		for(ZestStatement stmt : statements) {
			if(stmt instanceof ZestRequest) {
				if(currentZestRequestIndex == indexOfMessage){
					return statements.indexOf(stmt);
				}
				currentZestRequestIndex++;
			}
		}
		return 0;
	}

	//Gets a script containing all statements prior to the HttpMessage.
	private ZestScript getBeforeSubScript() {
		return getSubScript(0, getZestStatementIndex());
	}

	//Gets a script containing all statements after the HttpMessage.
	private ZestScript getAfterSubScript() {
		return getSubScript(getZestStatementIndex() + 1, getAllStatements().size());
	}

	private ZestScript getSubScript(int fromIndex, int toIndex) {
		ZestScript newScript = new ZestScript();
		List<ZestStatement> subStatements = getAllStatements().subList(fromIndex, toIndex);
		newScript.setStatements(subStatements);
		return newScript;
	}

	private List<ZestStatement> getAllStatements() {
		return this.script.getZestScript().getStatements();
	}


	public ZestRequest getRequest() {
		return (ZestRequest)getAllStatements().get(getZestStatementIndex());
	}
}
