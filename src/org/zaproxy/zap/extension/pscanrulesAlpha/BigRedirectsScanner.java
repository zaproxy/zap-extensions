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

package org.zaproxy.zap.extension.pscanrulesAlpha;

import java.text.MessageFormat;

import net.htmlparser.jericho.Source;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/**
 * Big Redirects passive scan rule 
 * https://code.google.com/p/zaproxy/issues/detail?id=1257
 * @author kingthorin+owaspzap@gmail.com
 */
public class BigRedirectsScanner extends PluginPassiveScanner{

	private static final String MESSAGE_PREFIX = "pscanalpha.bigredirectsscanner.";
	private static final int PLUGIN_ID = 10044;
	
	private PassiveScanThread parent = null;
	private static final Logger logger = Logger.getLogger(BigRedirectsScanner.class);
	
	@Override
	public void setParent(PassiveScanThread parent) {
		this.parent = parent;
	}

	@Override
	public void scanHttpRequestSend(HttpMessage msg, int id) {
		// Only checking the response for this plugin
	}
	
	@Override
	public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
		long start = System.currentTimeMillis();
	
		//isRedirect checks response code between 300 and 400, but 304 isn't actually a redirect it's "not modified"
		if(HttpStatusCode.isRedirection(msg.getResponseHeader().getStatusCode()) &&
				msg.getResponseHeader().getStatusCode() != 304) { //This response is a redirect
			int responseLocationHeaderURILength=0;
			String locationHeaderValue = msg.getResponseHeader().getHeader(HttpResponseHeader.LOCATION);
			if (locationHeaderValue !=null) {
				responseLocationHeaderURILength = locationHeaderValue.length();
			} 
			else { //No location header found
				logger.debug(MessageFormat.format("Though the response had a redirect status code it did not have a Location header.\nRequested URL: {0}",
						msg.getRequestHeader().getURI().toString()));
			}
		
			if (responseLocationHeaderURILength > 0) {
				int predictedResponseSize = getPredictedResponseSize(responseLocationHeaderURILength);
				int responseBodyLength=msg.getResponseBody().length();
				//Check if response is bigger than predicted
				if(responseBodyLength > predictedResponseSize) {
					//Response is larger than predicted so raise an alert
					Alert alert = new Alert(getPluginId(), Alert.RISK_LOW, Alert.WARNING, //PluginID, Risk, Reliability
						getName()); 
			    		alert.setDetail(
			    				getDescription(), //Description
			    				msg.getRequestHeader().getURI().toString(), //URI
			    				"",	// Param
			    				"", // Attack
			    				MessageFormat.format(Constant.messages.getString(MESSAGE_PREFIX + "extrainfo"),
			    						responseLocationHeaderURILength, locationHeaderValue, 
			    						predictedResponseSize, responseBodyLength), // Other info
			    				getSolution(), //Solution
			    				getReference(), //References
			    				"",	// Evidence 
			    				201, // CWE Id
			    				13,	// WASC Id
			    				msg); //HttpMessage
			    		parent.raiseAlert(id, alert);
				}
			}
		}
	    	if (logger.isDebugEnabled()) {
		    	logger.debug("\tScan of record " + id + " took " + (System.currentTimeMillis() - start) + " ms");
	    }
	}
	
    /** 
     * Gets the predicted size of the response body based on the 
     * URI specified in the response's Location header 
     * @param redirectURILength the length of the URI in the redirect response Location header
     * @return predictedResponseSize 
     */
	private int getPredictedResponseSize(int redirectURILength) {
		int predictedResponseSize = redirectURILength + 300;
		if (logger.isDebugEnabled()) {
			logger.debug("Original Response Location Header URI Length: "+ redirectURILength);
			logger.debug("Predicted Response Size: "+ predictedResponseSize);
		}
		return predictedResponseSize;
	}

	@Override
	public int getPluginId() {
		return PLUGIN_ID;
	}
	
	@Override
	public String getName(){
		return Constant.messages.getString(MESSAGE_PREFIX + "name");
	}
	
	private String getDescription() {
		return Constant.messages.getString(MESSAGE_PREFIX + "desc");
	}

	private String getSolution() {
		return Constant.messages.getString(MESSAGE_PREFIX + "soln");
	}

	private String getReference() {
		return Constant.messages.getString(MESSAGE_PREFIX + "refs");
	}

}

