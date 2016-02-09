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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import net.htmlparser.jericho.Source;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/**
 * Strict-Transport-Security Header Not Set passive scan rule 
 * https://github.com/zaproxy/zaproxy/issues/1169
 * @author kingthorin+owaspzap@gmail.com
 */
public class StrictTransportSecurityScanner extends PluginPassiveScanner{

	private static final String MESSAGE_PREFIX = "pscanalpha.stricttransportsecurity.";
	private static final int PLUGIN_ID = 10035;
	
	//max-age=0 disabled HSTS. It's allowed by the spec,
	//and is used to reset browser's settings for HSTS.
	//If found raise an INFO alert.
	//Pattern accounts for potential spaces and quotes
	private static final Pattern BAD_MAX_AGE_PATT = Pattern.compile("max-age\\s*=\\s*\'*\"*\\s*0\\s*\"*\'*\\s*", Pattern.CASE_INSENSITIVE);
	
	private enum VulnType {HSTS_MISSING, HSTS_MAX_AGE_DISABLED};
	
	private PassiveScanThread parent = null;
	private static final Logger logger = Logger.getLogger(StrictTransportSecurityScanner.class);
	
	@Override
	public void setParent(PassiveScanThread parent) {
		this.parent = parent;
	}

	@Override
	public void scanHttpRequestSend(HttpMessage msg, int id) {
		// Only checking the response for this plugin
	}
	
	private void raiseAlert(VulnType currentVT, String evidence, HttpMessage msg, int id) {
		Alert alert = new Alert(getPluginId(), //PluginID
					currentVT == VulnType.HSTS_MISSING ? Alert.RISK_LOW : Alert.RISK_INFO, //Risk (if missing low, otherwise info)
					Alert.CONFIDENCE_HIGH, //Reliability
					getAlertElement(currentVT, "name")); //Name
	    		alert.setDetail(
	    			getAlertElement(currentVT, "desc"), //Description
	    			msg.getRequestHeader().getURI().toString(), //URI
	    			"",	// Param
	    			"", // Attack
	    			"", // Other info
	    			getAlertElement(currentVT, "soln"), //Solution
	    			getAlertElement(currentVT, "refs"), //References
	    			evidence,	// Evidence
					16, // CWE-16: Configuration
					15,	//WASC-15: Application Misconfiguration
	    			msg); //HttpMessage
	    		parent.raiseAlert(id, alert);
	}
	
	@Override
	public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
		long start = System.currentTimeMillis();
		if (msg.getResponseBody().length() > 0 && 
				msg.getResponseHeader().isText() &&
				msg.getRequestHeader().isSecure()){ //No point reporting for non-SSL resources
			//Content available via both HTTPS and HTTP is a separate though related issue
			Vector<String> STSOption = msg.getResponseHeader().getHeaders("Strict-Transport-Security");
			if (STSOption == null) { // Header NOT found
					raiseAlert(VulnType.HSTS_MISSING, null, msg, id);
					return; //No point continuing
			} else { 
				for (String stsHeader : STSOption) {
					Matcher matcher = BAD_MAX_AGE_PATT.matcher(stsHeader);
					if (matcher.find()) { 
						String evidence = matcher.group();
						raiseAlert(VulnType.HSTS_MAX_AGE_DISABLED, evidence, msg, id);
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
	public String getName() {
		return Constant.messages.getString(MESSAGE_PREFIX + "scanner.name");
	}
	
	private String getAlertElement(VulnType currentVT, String element) {
		String elementValue="";
		switch (currentVT) {
			case HSTS_MISSING:
				elementValue=Constant.messages.getString(MESSAGE_PREFIX + element);
				break;
			case HSTS_MAX_AGE_DISABLED:
				elementValue=Constant.messages.getString(MESSAGE_PREFIX + "max.age." + element);
				break;
		}
		return elementValue;
	}

}
