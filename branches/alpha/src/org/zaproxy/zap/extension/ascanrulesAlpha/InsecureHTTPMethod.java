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
package org.zaproxy.zap.extension.ascanrulesAlpha;

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;

import org.apache.commons.httpclient.Header;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.methods.OptionsMethod;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractHostPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.model.Vulnerabilities;
import org.zaproxy.zap.model.Vulnerability;

/**
* a scanner that looks for known insecure HTTP methods on the host
* 
* @author 70pointer
*
*/
public class InsecureHTTPMethod extends AbstractHostPlugin {

	/**
	 * the set of methods that we know are unsafe.  There may be others.
	 */
	static final Set <String> insecureMethods = new LinkedHashSet<String>(Arrays.asList(new String [] 
			{
			"TRACE",
			"TRACK",
			"CONNECT"
			}
			));

	/**
	 * details of the vulnerability which we are attempting to find 
	 * 45 = "Fingerprinting"
	 */
	private static Vulnerability vuln = Vulnerabilities.getVulnerability("wasc_45");

	/**
	 * the logger object
	 */
	private static Logger log = Logger.getLogger(InsecureHTTPMethod.class);


	/**
	 * returns the plugin id
	 */
	@Override
	public int getId() {
		return 90028;
	}

	/**
	 * returns the name of the plugin
	 */
	@Override
	public String getName() {
		return Constant.messages.getString("ascanalpha.insecurehttpmethod.name");
	}

	@Override
	public String[] getDependency() {
		return null;
	}

	@Override
	public String getDescription() {
		if (vuln != null) {
			return vuln.getDescription();
		}
		return "Failed to load vulnerability description from file";
	}

	@Override
	public int getCategory() {
		return Category.SERVER;
	}

	@Override
	public String getSolution() {
		if (vuln != null) {
			return vuln.getSolution();
		}
		return "Failed to load vulnerability solution from file";
	}

	@Override
	public String getReference() {
		if (vuln != null) {
			StringBuilder sb = new StringBuilder();
			for (String ref : vuln.getReferences()) {
				if (sb.length() > 0) {
					sb.append('\n');
				}
				sb.append(ref);
			}
			return sb.toString();
		}
		return "Failed to load vulnerability reference from file";
	}

	@Override
	public void init() {		
	}


	@Override
	public void scan() {
		try {
			URI uri = this.getBaseMsg().getRequestHeader().getURI();
			String allowedmethods = null;
			String publicmethods = null;
			
			//send an "OPTIONS" request
			HttpClient client = new HttpClient();
			OptionsMethod optionsMethod = new OptionsMethod(uri.getScheme() +"://" + uri.getAuthority());
			int statusCode = client.executeMethod(optionsMethod);
			if (statusCode != HttpStatus.SC_OK) {
				log.error("The OPTIONS method failed:"+ statusCode);
				return;
			}
			
			//TODO: use HttpHeader.METHODS_ALLOW and HttpHeader.METHODS_PUBLIC, once this change is in the core. 
			Header allowedmethodsHeader = optionsMethod.getResponseHeader("Allow");			
			Header publicmethodsHeader = optionsMethod.getResponseHeader("Public");
			if ( allowedmethodsHeader != null) allowedmethods = allowedmethodsHeader.getValue();
			if ( publicmethodsHeader != null) publicmethods = publicmethodsHeader.getValue();
			
			optionsMethod.releaseConnection();
						
			if ( allowedmethods == null) {
				//nothing to see here. Move along now.
				return;
			}
			//if the "Public" response is present (for IIS), use that to determine the enabled methods.
			if ( publicmethods != null) {
				allowedmethods = publicmethods;
			}
			
			for (String enabledmethod: allowedmethods.split(",")) {
				for (String insecureMethod : insecureMethods) {
					if (enabledmethod.toUpperCase().equals(insecureMethod)) {
						//bingo.
						bingo(	Alert.RISK_MEDIUM, 
								Alert.WARNING,
								Constant.messages.getString("ascanalpha.insecurehttpmethod.name") + " - "+ insecureMethod,
								Constant.messages.getString("ascanalpha.insecurehttpmethod.desc"), 
								null, // originalMessage.getRequestHeader().getURI().getURI(),
								null, // parameter being attacked: none.
								null,  // attack
								Constant.messages.getString("ascanalpha.insecurehttpmethod.extrainfo", allowedmethods),
								Constant.messages.getString("ascanalpha.insecurehttpmethod.soln"),
								Constant.messages.getString("ascanalpha.insecurehttpmethod.evidence", insecureMethod, allowedmethods),
								this.getBaseMsg()   //originalMessage
								);
					} else {
						if ( log.isDebugEnabled() ) {
							log.debug(enabledmethod + "!="+insecureMethod);
						}
					}
				}
			}
			
		} catch (Exception e) {
			log.error("Error scanning a Host for Insecure HTTP Methods: " + e.getMessage(), e);
		}
	}

	@Override
	public int getRisk() {
		return Alert.RISK_MEDIUM; 
	}

	@Override
	public int getCweId() {
		return 200;  // Information Exposure (primarily via TRACK / TRACE)
	}

	@Override
	public int getWascId() {
		return 45;  //Fingerprinting
	}

}
