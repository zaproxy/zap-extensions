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

import java.util.Vector;

import net.htmlparser.jericho.Source;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;

public class XFrameOptionScanner extends PluginPassiveScanner {

	private PassiveScanThread parent = null;
	/**
	 * Prefix for internationalised messages used by this rule
	 */
	private static final String MESSAGE_PREFIX = "pscanrules.xframeoptionsscanner.";
	private static final int PLUGIN_ID = 10020;
	
	@Override
	public void scanHttpRequestSend(HttpMessage msg, int id) {
		
	}

	@Override
	public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
		if (msg.getResponseBody().length() > 0 && msg.getResponseHeader().isText()){
			Vector<String> xFrameOption = msg.getResponseHeader().getHeaders(HttpHeader.X_FRAME_OPTION);
			if (xFrameOption != null) {
				for (String xFrameOptionParam : xFrameOption) {
					if (xFrameOptionParam.toLowerCase().indexOf("deny") < 0 && xFrameOptionParam.toLowerCase().indexOf("sameorigin") < 0 && xFrameOptionParam.toLowerCase().indexOf("allow-from") < 0) {
						this.raiseAlert(msg, id, xFrameOptionParam, false);
					}
				}
			} else {
				this.raiseAlert(msg, id, "", true);
			}
		}
	}

	private void raiseAlert(HttpMessage msg, int id, String xFrameOption, boolean isXFrameOptionsMissing) {
		Alert alert = new Alert(getPluginId(), Alert.RISK_MEDIUM, Alert.CONFIRMED, 
		    	getName());
		    	alert.setDetail(
		    		getDescription(isXFrameOptionsMissing), 
		    	    msg.getRequestHeader().getURI().toString(),
		    	    xFrameOption,
		    	    "", 
		    	    "",
		    	    getSolution(),
		            getReference(), 
		            "", // No evidence
		            0,	
		            0,	
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
	
	private String getDescription(boolean isMissing) {
		if (isMissing) //Not set at all
			return Constant.messages.getString(MESSAGE_PREFIX + "missing.desc");
		else //Set improperly?
			return Constant.messages.getString(MESSAGE_PREFIX + "desc");
	}

	private String getSolution() {
		return Constant.messages.getString(MESSAGE_PREFIX + "soln");
	}

	private String getReference() {
		return Constant.messages.getString(MESSAGE_PREFIX + "refs");
	}
}
