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

import java.util.List;
import java.util.Vector;

import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.HTMLElementName;
import net.htmlparser.jericho.Source;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;

public class XFrameOptionScanner extends PluginPassiveScanner {

	private PassiveScanThread parent = null;
	/**
	 * Prefix for internationalised messages used by this rule
	 */
	private static final String MESSAGE_PREFIX = "pscanrules.xframeoptionsscanner.";
	private static final int PLUGIN_ID = 10020;
		
	private enum VulnType {XFO_MISSING, XFO_MULTIPLE_HEADERS, XFO_META, XFO_MALFORMED_SETTING};
	
	@Override
	public void scanHttpRequestSend(HttpMessage msg, int id) {
		
	}

	@Override
	public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
		boolean includeErrorResponses=true;
		switch (this.getLevel()) {
			case HIGH:	includeErrorResponses=false; break;  
			case MEDIUM: 					
			case DEFAULT: 
			case LOW: 		
			case OFF: } 
		
		if (msg.getResponseBody().length() > 0 && msg.getResponseHeader().isText()){
			int responseStatus = msg.getResponseHeader().getStatusCode();
			// If it's an error and we're not including error responses then just return without alerting
			if (!includeErrorResponses && 
					(HttpStatusCode.isServerError(responseStatus) ||
					HttpStatusCode.isClientError(responseStatus))) {
				return;
			} 
		Vector<String> xFrameOption = msg.getResponseHeader().getHeaders(HttpHeader.X_FRAME_OPTION);
			if (xFrameOption != null) {
				for (String xFrameOptionParam : xFrameOption) {
					if (xFrameOptionParam.toLowerCase().indexOf("deny") < 0 && xFrameOptionParam.toLowerCase().indexOf("sameorigin") < 0 && xFrameOptionParam.toLowerCase().indexOf("allow-from") < 0) {
						raiseAlert(msg, id, xFrameOptionParam, VulnType.XFO_MALFORMED_SETTING);
					}
				}
				if (xFrameOption.size() > 1) { //Multiple headers
					raiseAlert(msg, id, "", VulnType.XFO_MULTIPLE_HEADERS);
				}
			} else {
				raiseAlert(msg, id, "", VulnType.XFO_MISSING);
			}
			
			String metaXFO = getMetaXFOEvidence(source);
			
			if (metaXFO != null) {
				//XFO found defined by META tag
				raiseAlert(msg, id, metaXFO, VulnType.XFO_META);
			}
		}
	}

	private void raiseAlert(HttpMessage msg, int id, String evidence, VulnType currentVT) {
		Alert alert = new Alert(getPluginId(), Alert.RISK_MEDIUM, Alert.CONFIDENCE_MEDIUM, 
		    	getAlertElement(currentVT, "name"));
		    	alert.setDetail(
		    		getAlertElement(currentVT, "desc"), 
		    	    msg.getRequestHeader().getURI().toString(),
		    	    "",//Param
		    	    "", //Attack
		    	    "", //OtherInfo
		    	    getAlertElement(currentVT, "soln"),
		    	    getAlertElement(currentVT, "refs"), 
		            evidence, //Evidence
		            16,	//CWE-16: Configuration
		            15,	//WASC-15: Application Misconfiguration 
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
	
	private String getAlertElement(VulnType currentVT, String element) {
		switch (currentVT) {
			case XFO_MISSING:
				return Constant.messages.getString(MESSAGE_PREFIX + "missing." + element);
			case XFO_MULTIPLE_HEADERS:
				return Constant.messages.getString(MESSAGE_PREFIX + "multiple.header." + element);
			case XFO_META:
				return Constant.messages.getString(MESSAGE_PREFIX + "compliance.meta." + element);
			case XFO_MALFORMED_SETTING:
				return Constant.messages.getString(MESSAGE_PREFIX + "compliance.malformed.setting." + element);
			default:
				return "";
		}
	}
	
	/**
	 * Checks the source of the response for XFO being set via a META tag which is explicitly
	 * not supported per the spec (rfc7034). 
	 * 
	 * @param source the source of the response to be analyzed.
	 * @return returns a string if XFO was set via META (for use as alert evidence) otherwise return {@code null}.
	 * @see <a href="https://tools.ietf.org/html/rfc7034#section-4"> RFC 7034 Section 4</a>
	 */
	private String getMetaXFOEvidence(Source source) {
		List<Element> metaElements = source.getAllElements(HTMLElementName.META);
		String httpEquiv;

		if (metaElements != null) {
			for (Element metaElement : metaElements) {
				httpEquiv = metaElement.getAttributeValue("http-equiv");
				if (HttpHeader.X_FRAME_OPTION.equalsIgnoreCase(httpEquiv)) {
					return httpEquiv;
				}
			}
		}
		return null;
	}
	
}
