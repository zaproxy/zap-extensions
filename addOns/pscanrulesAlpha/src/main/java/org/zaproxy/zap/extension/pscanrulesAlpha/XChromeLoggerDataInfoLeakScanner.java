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
 *   http://www.apache.org/licenses/LICENSE-2.0 
 *   
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS, 
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
 * See the License for the specific language governing permissions and 
 * limitations under the License. 
 */

package org.zaproxy.zap.extension.pscanrulesAlpha;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Vector;

import net.htmlparser.jericho.Source;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;
import org.parosproxy.paros.extension.encoder.Base64;

/**
 * X-ChromeLogger-Data header information leak passive scan rule 
 * @author kingthorin+owaspzap@gmail.com
 */
public class XChromeLoggerDataInfoLeakScanner extends PluginPassiveScanner{

	private static final String MESSAGE_PREFIX = "pscanalpha.xchromeloggerdata.";
	private static final int PLUGIN_ID = 10052;
	
	private PassiveScanThread parent = null;
	private static final Logger logger = Logger.getLogger(XChromeLoggerDataInfoLeakScanner.class);
	
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

		Vector<String> xcldHeader = msg.getResponseHeader().getHeaders("X-ChromeLogger-Data"); //Get the header(s)
		Vector<String> xcpdHeader = msg.getResponseHeader().getHeaders("X-ChromePhp-Data"); //Add any header(s) using the alternate name
		
		List<String> loggerHeaders = new ArrayList<String>(2);
		
		if(xcldHeader != null && !xcldHeader.isEmpty()) {
			loggerHeaders.addAll(xcldHeader);
		}
		if(xcpdHeader !=null && !xcpdHeader.isEmpty()) {
			loggerHeaders.addAll(xcpdHeader);
		}

		if (!loggerHeaders.isEmpty()) { //Header(s) Found
			for (String xcldField : loggerHeaders) {
					Alert alert = new Alert(getPluginId(), Alert.RISK_MEDIUM, Alert.CONFIDENCE_HIGH, //PluginID, Risk, Reliability
						getName()); 
		    			alert.setDetail(
		    					getDescription(), //Description
		    					msg.getRequestHeader().getURI().toString(), //URI
		    					"",	// Param
		    					"", // Attack
		    					getOtherInfo(xcldField), // Other info
		    					getSolution(), //Solution
		    					getReference(), //References
		    					xcldField,	// Evidence 
		    					200, // CWE Id 
		    					13,	// WASC Id 
		    					msg); //HttpMessage
		    		parent.raiseAlert(id, alert);
				}
			}
	    	if (logger.isDebugEnabled()) {
	    		logger.debug("\tScan of record " + id + " took " + (System.currentTimeMillis() - start) + " ms");
	    	}
	}

	@Override
	public int getPluginId() {
		return PLUGIN_ID;
	}
	
	@Override
	public String getName() {
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
	
	private String getOtherInfo(String headerValue) {
		try {
    		byte[] decodedByteArray = Base64.decode(headerValue);
            return Constant.messages.getString(MESSAGE_PREFIX + "otherinfo.msg") + "\n" + new String(decodedByteArray, StandardCharsets.UTF_8);
		} catch (IOException e) {
            return Constant.messages.getString(MESSAGE_PREFIX + "otherinfo.error") + " " + headerValue;
		}
	}

}
