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
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;

public class CacheControlScanner extends PluginPassiveScanner {

	/**
	 * Prefix for internationalised messages used by this rule
	 */
	private static final String MESSAGE_PREFIX = "pscanrules.cachecontrolscanner.";
	
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
		if (msg.getRequestHeader().isSecure() && !msg.getRequestHeader().getURI().toString().toLowerCase().endsWith(".css") && !msg.getResponseHeader().isImage() && msg.getResponseBody().length() > 0) {
			Vector<String> cacheControlVect = msg.getResponseHeader().getHeaders(HttpHeader.CACHE_CONTROL);
			String cacheControlHeaders = (cacheControlVect != null) ? cacheControlVect.toString().toLowerCase() : "";

			if (cacheControlHeaders.isEmpty() || //No Cache-Control header at all 
					cacheControlHeaders.indexOf("no-store") < 0 || 
					cacheControlHeaders.indexOf("no-cache") < 0 || 
					cacheControlHeaders.indexOf("must-revalidate") < 0 ||
					cacheControlHeaders.indexOf("private") < 0) {
				this.raiseAlert(msg, id, null); //Didn't find a header on the request that matched the criteria
			}
			
			Vector<String> pragma = msg.getResponseHeader().getHeaders(HttpHeader.PRAGMA);
			if (pragma != null) {
				for (String pragmaDirective : pragma) {
					if (pragmaDirective.toLowerCase().indexOf("no-cache") < 0){
						this.raiseAlert(msg, id, pragmaDirective);
					}
				}
			}
		}
	}

	private void raiseAlert(HttpMessage msg, int id, String cacheControl) {
	    Alert alert = new Alert(getPluginId(), Alert.RISK_LOW, Alert.CONFIDENCE_MEDIUM, 
		    	getName());
		    	alert.setDetail(
		    	    getDescription(), 
		    	    msg.getRequestHeader().getURI().toString(),
		    	    "",
		    	    "", "", 
		    	    getSolution(), 
		            getReference(), 
		            cacheControl, // Highlight if it's wrong...
		            525, //CWE
		            13,	// WASC-13: Information Leakage
		            msg);
	
    	parent.raiseAlert(id, alert);
	}
	
	@Override
	public int getPluginId() {
		return 10015;
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

}
