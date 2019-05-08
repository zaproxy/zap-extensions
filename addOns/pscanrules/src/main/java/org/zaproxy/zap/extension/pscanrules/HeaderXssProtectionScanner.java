/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
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
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;

/**
 * a scanner to passively scan for the absence or insecure configuration of the X-XSS-Protection HTTP response header
 */
public class HeaderXssProtectionScanner extends PluginPassiveScanner {

	/**
	 * Prefix for internationalised messages used by this rule
	 */
	private static final String MESSAGE_PREFIX = "pscanrules.headerxssprotectionscanner.";
	
	private PassiveScanThread parent = null;
	
	@Override
	public void setParent(PassiveScanThread parent) {
		this.parent = parent;
	}

	@Override
	public void scanHttpRequestSend(HttpMessage msg, int id) {
		
	}

	@Override
	public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
		if (AlertThreshold.LOW.equals(this.getAlertThreshold())) {
			if (!msg.getResponseHeader().isText()) {
				return;
			}
		} else {
			if (!msg.getResponseHeader().isHtml()) {
				return;
			}
			if (HttpStatusCode.isRedirection(
					msg.getResponseHeader().getStatusCode())) {
				return;
			}

		}
		boolean headerPresent = false;
		Vector<String> xssHeaderProtection = msg.getResponseHeader().getHeaders(HttpHeader.X_XSS_PROTECTION);
		boolean possibleXSSCarrier = msg.getResponseBody().length() > 0;
		if (xssHeaderProtection != null) {
			headerPresent = true;
			if (possibleXSSCarrier){
				for (String xssHeaderProtectionParam : xssHeaderProtection) {
					String xssHeaderProtectionParamPart1 = xssHeaderProtectionParam.split(";")[0];
					if ( ! xssHeaderProtectionParamPart1.equals("1") ) {
						this.raiseAlert(msg, id, xssHeaderProtectionParam);
					}
				}
			} 
		}
		if ( (! headerPresent) && possibleXSSCarrier) { 
			//no header, so raise an alert
			this.raiseAlert(msg, id, null);
		}
	}
	
	private void raiseAlert(HttpMessage msg, int id, String xssHeaderProtection) {
		Alert alert = new Alert(getPluginId(), Alert.RISK_LOW, Alert.CONFIDENCE_MEDIUM,  getName());
		alert.setDetail(
					Constant.messages.getString(MESSAGE_PREFIX + "desc"), 
		    	    msg.getRequestHeader().getURI().toString(),
		    	    HttpHeader.X_XSS_PROTECTION, //parameter
		    	    "", 					//attack
		    	    Constant.messages.getString(MESSAGE_PREFIX + "extrainfo"),		//other info
		    	    Constant.messages.getString(MESSAGE_PREFIX + "soln"),			//solution 
		    	    Constant.messages.getString(MESSAGE_PREFIX + "refs"),			//refs 
		            (xssHeaderProtection!= null?HttpHeader.X_XSS_PROTECTION+": "+xssHeaderProtection:""), 	//evidence, if any
		            933, //CWE-933: OWASP Top Ten 2013 Category A5 - Security Misconfiguration
		            14,  //WASC-14: Server Misconfiguration
		            msg);
	
    	parent.raiseAlert(id, alert);
	}

	@Override
	public int getPluginId() {
		return 10016;
	}
	
	@Override
	public String getName() {
		return Constant.messages.getString(MESSAGE_PREFIX + "name");
	}
	
}
