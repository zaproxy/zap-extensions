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

import net.htmlparser.jericho.Source;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/**
 * Content Security Policy Header Missing passive scan rule 
 * https://github.com/zaproxy/zaproxy/issues/1169
 * @author kingthorin+owaspzap@gmail.com
 */
public class ContentSecurityPolicyMissingScanner extends PluginPassiveScanner{

	private static final String MESSAGE_PREFIX = "pscanalpha.contentsecuritypolicymissing.";
	private static final int PLUGIN_ID = 10038;
	
	private PassiveScanThread parent = null;
	private static final Logger logger = Logger.getLogger(ContentSecurityPolicyMissingScanner.class);
	
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
		
		if (! msg.getResponseHeader().isHtml() &&
				! this.getLevel().equals(AlertThreshold.LOW)) {
			// Only really applies to HTML responses, but also check on Low threshold
			return;
		}
	
		//Get the various CSP headers
		boolean cspHeaderFound = false, cspROHeaderFound = false, xCspHeaderFound = false, xWebKitHeaderFound=false;
		
		//Content-Security-Policy is supported by Chrome 25+, Firefox 23+, Safari 7+, but not but Internet Exploder
		Vector<String> cspOptions = msg.getResponseHeader().getHeaders("Content-Security-Policy");
		//If it's not null or empty then we found one
		if (cspOptions != null && cspOptions.isEmpty() == false) { 
			cspHeaderFound = true;
		}
		
		Vector<String> cspROOptions = msg.getResponseHeader().getHeaders("Content-Security-Policy-Report-Only");
		//If it's not null or empty then we found one
		if (cspROOptions != null && cspROOptions.isEmpty() == false) { 
			cspROHeaderFound = true;
		}
		
		//X-Content-Security-Policy is an older header, supported by Firefox 4.0+, and IE 10+ (in a limited fashion)
		Vector<String> xcspOptions = msg.getResponseHeader().getHeaders("X-Content-Security-Policy");
		//If it's not null or empty then we found one
		if (xcspOptions != null && xcspOptions.isEmpty() == false) { 
			xCspHeaderFound = true;
		}
		
		//X-WebKit-CSP is supported by Chrome 14+, and Safari 6+
		Vector<String> xwkcspOptions = msg.getResponseHeader().getHeaders("X-WebKit-CSP");
		//If it's not null or empty then we found one
		if (xwkcspOptions !=null && xwkcspOptions.isEmpty() == false) { 
			xWebKitHeaderFound = true;
		}
		
		//TODO: parse the CSP values out, and look at them in more detail.  In particular, look for things like...
		//script-src *
		//style-src *
		//img-src *
		//connect-src *
		//font-src *
		//object-src *
		//media-src *
		//frame-src *
		//script-src 'unsafe-inline'
		//script-src 'unsafe-eval'

		if (!cspHeaderFound ||
				(this.getLevel().equals(AlertThreshold.LOW) &&
						(!xCspHeaderFound || !xWebKitHeaderFound))) {
			// Always report if the latest header isnt found,
			// but only report if the older ones arent present at Low threshold 
			Alert alert = new Alert(getPluginId(), // PluginID
					cspROHeaderFound ? Alert.RISK_INFO : Alert.RISK_LOW, // Risk
					Alert.CONFIDENCE_MEDIUM, // Reliability
					getName());
			alert.setDetail(getAlertAtrribute("desc"), // Description
					msg.getRequestHeader().getURI().toString(), // URI
					"", // Param
					"", // Attack
					"", // Other info
					getAlertAtrribute("soln"), // Solution
					getAlertAtrribute("refs"), // References
					"", // Evidence
					16, // CWE-16: Configuration
					15, // WASC-15: Application Misconfiguration
					msg); // HttpMessage
			parent.raiseAlert(id, alert);
		}
		
		if (cspROHeaderFound) {
			Alert alert = new Alert(getPluginId(), Alert.RISK_INFO, Alert.CONFIDENCE_MEDIUM, //PluginID, Risk, Reliability
					getAlertAtrribute("ro.name")); 
				alert.setDetail(
						getAlertAtrribute("ro.desc"), //Description
						msg.getRequestHeader().getURI().toString(), //URI
						"",	// Param
						"", // Attack
						"", // Other info
						getAlertAtrribute("soln"), //Solution
						getAlertAtrribute("ro.refs"), //References
						"",	// Evidence
						16, // CWE-16: Configuration
						15,	// WASC-15: Application Misconfiguration
						msg); //HttpMessage
		   	parent.raiseAlert(id, alert);
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
	
	private String getAlertAtrribute(String key) {
		return Constant.messages.getString(MESSAGE_PREFIX + key);
	}

}