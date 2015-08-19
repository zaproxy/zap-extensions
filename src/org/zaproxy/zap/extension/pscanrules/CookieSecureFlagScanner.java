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
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;


public class CookieSecureFlagScanner extends PluginPassiveScanner {

	/**
	 * Prefix for internationalised messages used by this rule
	 */
	private static final String MESSAGE_PREFIX = "pscanrules.cookiesecureflagscanner.";
	
	private PassiveScanThread parent = null;
	//private Logger logger = Logger.getLogger(this.getClass());

	@Override
	public void setParent (PassiveScanThread parent) {
		this.parent = parent;
	}

	@Override
	public void scanHttpRequestSend(HttpMessage msg, int id) {
		// Ignore
	}

	@Override
	public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
		if (!msg.getRequestHeader().isSecure()) {
			// If SSL isn't used then the Secure flag has not to be checked
			return;
		}
		
		Vector<String> cookies1 = msg.getResponseHeader().getHeaders(HttpHeader.SET_COOKIE);

		if (cookies1 != null) {
			for (String cookie : cookies1) {
				if (cookie.toLowerCase().indexOf("secure") < 0) {
					this.raiseAlert(msg, id, cookie);
				}
			}
		}

		Vector<String> cookies2 = msg.getResponseHeader().getHeaders(HttpHeader.SET_COOKIE2);
		
		if (cookies2 != null) {
			for (String cookie : cookies2) {
				if (cookie.toLowerCase().indexOf("secure") < 0) {
					this.raiseAlert(msg, id, cookie);
				}
			}
		}
	}
	
	private void raiseAlert(HttpMessage msg, int id, String cookie) {
	    Alert alert = new Alert(getPluginId(), Alert.RISK_LOW, Alert.CONFIDENCE_MEDIUM, 
		    	"Cookie set without secure flag");
		    	alert.setDetail(
		    	    "A cookie has been set without the secure flag, which means that the cookie can be accessed via unencrypted connections.", 
		    	    msg.getRequestHeader().getURI().toString(),
		    	    cookie, "", "",
		    	    "Whenever a cookie contains sensitive information or is a session token, then it should always be passed using an encrypted tunnel. " +
                            "Ensure that the secure flag is set for cookies containing such sensitive information.", 
		            "http://www.owasp.org/index.php/Testing_for_cookies_attributes_(OWASP-SM-002)", 
		            cookie, // evidence
		            614, // CWE Id
		            13,	// WASC Id - Info leakage
		            msg);
	
    	parent.raiseAlert(id, alert);

	}

	@Override
	public int getPluginId() {
		return 10011;
	}

	@Override
	public String getName() {
		return Constant.messages.getString(MESSAGE_PREFIX + "name");
	}
}
