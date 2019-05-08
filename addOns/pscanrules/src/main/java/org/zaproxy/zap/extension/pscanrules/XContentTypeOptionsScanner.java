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
package org.zaproxy.zap.extension.pscanrules;

import java.util.Locale;
import java.util.Vector;

import net.htmlparser.jericho.Source;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

public class XContentTypeOptionsScanner extends PluginPassiveScanner {

	private PassiveScanThread parent = null;
	/**
	 * Prefix for internationalized messages used by this rule
	 */
	private static final String MESSAGE_PREFIX = "pscanrules.xcontenttypeoptionsscanner.";
	private static final int PLUGIN_ID = 10021;
	
	@Override
	public void scanHttpRequestSend(HttpMessage msg, int id) {
		
	}

	@Override
	public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
		boolean includeErrorRedirectResponses = false;
		switch (this.getAlertThreshold()) {
			case LOW: 
				includeErrorRedirectResponses = true; break;
			case HIGH:  
			case MEDIUM: 					
			default:
		}
		if (msg.getResponseBody().length() > 0) {
			int responseStatus = msg.getResponseHeader().getStatusCode();
			// If it's an error and we're not including error responses then just return without alerting
			if (!includeErrorRedirectResponses && 
					(HttpStatusCode.isServerError(responseStatus) ||
					HttpStatusCode.isClientError(responseStatus) ||
					HttpStatusCode.isRedirection(responseStatus))) {
				return;
			} 
			Vector<String> xContentTypeOptions = msg.getResponseHeader().getHeaders(HttpHeader.X_CONTENT_TYPE_OPTIONS);
			if (xContentTypeOptions == null) {
				this.raiseAlert(msg, id, "");
			} else {
				for (String xContentTypeOptionsDirective : xContentTypeOptions) {
					//'nosniff' is currently the only defined value for this header, so this logic is ok
					if (xContentTypeOptionsDirective.toLowerCase(Locale.ROOT).indexOf("nosniff") < 0) {
						this.raiseAlert(msg, id, xContentTypeOptionsDirective);
					}
				}
			} 
		}
	}
		
	private void raiseAlert(HttpMessage msg, int id, String xContentTypeOption) {
		Alert alert = new Alert(getPluginId(), Alert.RISK_LOW, Alert.CONFIDENCE_MEDIUM, 
		    	getName());
		    	alert.setDetail(
		    		getDescription(), // Desc
		    	    msg.getRequestHeader().getURI().toString(), // URL
		    	    HttpHeader.X_CONTENT_TYPE_OPTIONS, // Parameter
		    	    "", // Attack
		    	    getOtherInfo(), // OtherInfo
		    	    getSolution(), // Soln 
		            getReference(), // Refs
		            xContentTypeOption, // Evidence
		            16,	// CWE-16: Configuration
		            15,	// WASC15: Application Misconfiguration
		            msg);
	
    	parent.raiseAlert(id, alert);
	}

	@Override
	public void setParent(PassiveScanThread parent) {
			this.parent = parent;
	}

	@Override
	public String getName() {
		return Constant.messages.getString(MESSAGE_PREFIX + "name");
	}
	
	@Override
	public int getPluginId() {
		return PLUGIN_ID;
	}
	
	private String getDescription() {
			return Constant.messages.getString(MESSAGE_PREFIX + "desc");
	}

	private String getOtherInfo() {
		return Constant.messages.getString(MESSAGE_PREFIX + "otherinfo");
	}
	
	private String getSolution() {
		return Constant.messages.getString(MESSAGE_PREFIX + "soln");
	}

	private String getReference() {
		return Constant.messages.getString(MESSAGE_PREFIX + "refs");
	}
}
