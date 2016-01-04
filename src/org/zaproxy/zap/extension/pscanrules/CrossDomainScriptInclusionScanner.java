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

import java.util.List;

import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.HTMLElementName;
import net.htmlparser.jericho.Source;

import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;


public class CrossDomainScriptInclusionScanner extends PluginPassiveScanner {

	/**
	 * Prefix for internationalised messages used by this rule
	 */
	private static final String MESSAGE_PREFIX = "pscanrules.crossdomainscriptinclusionscanner.";
	private static final int PLUGIN_ID = 10017;
	
	private PassiveScanThread parent = null;
	private static final Logger logger = Logger.getLogger(CrossDomainScriptInclusionScanner.class);
	
	@Override
	public void scanHttpRequestSend(HttpMessage msg, int id) {
		
	}

	@Override
	public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
		if (msg.getResponseBody().length() > 0 && msg.getResponseHeader().isText()){
			List<Element> sourceElements = source.getAllElements(HTMLElementName.SCRIPT);
			if (sourceElements != null) {
				for (Element sourceElement : sourceElements) {
					String src = sourceElement.getAttributeValue("src");
						if (src != null && isScriptFromOtherDomain(msg.getRequestHeader().getHostName(), src)) {
							this.raiseAlert(msg, id, src);
						}	
				}	
			}
		}
	}

	private void raiseAlert(HttpMessage msg, int id, String crossDomainScript) {
		Alert alert = new Alert(getPluginId(), Alert.RISK_LOW, Alert.CONFIDENCE_MEDIUM, 
		    	getName());
		    	alert.setDetail(
		    		getDescription(), 
		    	    msg.getRequestHeader().getURI().toString(),
		    	    crossDomainScript,
		    	    "", 
		    	    "",
		    	    getSolution(), 
		            "", 
		            crossDomainScript, // evidence
		            829,	// CWE Id 829 - Inclusion of Functionality from Untrusted Control Sphere
		            15,	// WASC Id 15 - Application Misconfiguration
		            msg);
	
    	parent.raiseAlert(id, alert);
	}
	
	@Override
	public void setParent(PassiveScanThread parent) {
		this.parent = parent;		
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
	
	private boolean isScriptFromOtherDomain (String host, String scriptURL){
		if (!scriptURL.startsWith("//") && (scriptURL.startsWith("/") || scriptURL.startsWith("./") || scriptURL.startsWith("../"))) {
			return false;
		}
		boolean result = false;
		try {
			URI scriptURI = new URI(scriptURL, true);
			String scriptHost = scriptURI.getHost();
			if(scriptHost != null && !scriptHost.toLowerCase().equals(host.toLowerCase())){
				result = true;
			} 
		}catch (URIException e) {
			logger.debug("Error: " + e.getMessage());
		}
		return result;
	}
}
