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

import java.util.Vector;
import java.util.regex.Pattern;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

import net.htmlparser.jericho.Source;

/**
 * Server Header Version Information Leak passive scan rule 
 * https://github.com/zaproxy/zaproxy/issues/1169
 * @author kingthorin+owaspzap@gmail.com
 */
public class ServerHeaderInfoLeakScanner extends PluginPassiveScanner{

	private static final String MESSAGE_PREFIX = "pscanalpha.serverheaderversioninfoleak.";
	private static final int PLUGIN_ID = 10036;
	
	private PassiveScanThread parent = null;
	private static final Logger logger = Logger.getLogger(ServerHeaderInfoLeakScanner.class);
	
	private final static Pattern VERSION_PATTERN = Pattern.compile(".*\\d.*");
	
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
	
		Vector<String> serverOption = msg.getResponseHeader().getHeaders("Server");
		if (serverOption != null) { //Header Found
			if (Plugin.AlertThreshold.LOW.equals(this.getLevel())) {
				// If we are operating with an LOW treshhold, detecting a
				// "server" header is enough to raise an alert.
				Alert alert = new Alert(getPluginId(), Alert.RISK_LOW, Alert.CONFIDENCE_MEDIUM,																								
						getName());
				alert.setDetail(getDescription(), // Description
						msg.getRequestHeader().getURI().toString(), // URI
						"", // Param
						"", // Attack
						"", // Other info
						getSolution(), // Solution
						getReference(), // References
						String.join(", ",serverOption), // Evidence - Return the Server Header info
						200, // CWE Id
						13, // WASC Id
						msg); // HttpMessage
				parent.raiseAlert(id, alert);
			}
			if (Plugin.AlertThreshold.DEFAULT.equals(this.getLevel()) || Plugin.AlertThreshold.MEDIUM.equals(this.getLevel())) {
				//It is set so lets check it. Should only be one but it's a vector so iterate to be sure.
				for (String serverDirective : serverOption) {
					boolean matched = VERSION_PATTERN.matcher(serverDirective).matches();								
					if (matched) { //See if there's any version info.
						//While an alpha string might be the server type (Apache, Netscape, IIS, etc) 
						//that's much less of a head-start than actual version details.
						Alert alert = new Alert(getPluginId(), Alert.RISK_LOW, Alert.CONFIDENCE_MEDIUM, //PluginID, Risk, Reliability
							getName()); 
			    			alert.setDetail(
			    					getDescription(), //Description
			    					msg.getRequestHeader().getURI().toString(), //URI
			    					"",	// Param
			    					"", // Attack
			    					"", // Other info
			    					getSolution(), //Solution
			    					getReference(), //References
			    					serverDirective,	// Evidence - Return the Server Header info
			    					200, // CWE Id 
			    					13,	// WASC Id 
			    					msg); //HttpMessage
			    		parent.raiseAlert(id, alert);
					}
				}
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

