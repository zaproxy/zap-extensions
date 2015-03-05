/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2012 The ZAP development team
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

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import net.htmlparser.jericho.Source;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;


/**
 * A class to passively scan responses for HTTP header signatures that indicate that the web server is vulnerable to the HeartBleed OpenSSL vulnerability 
 * @author 70pointer@gmail.com
 *
 */
public class HeartBleedScanner extends PluginPassiveScanner {	

	private PassiveScanThread parent = null;
	
	/**
	 * a pattern to identify the version reported in the header.  
	 * This works for Apache2 (subject to the reported version containing back-ported security fixes).
	 * There is no equivalent way to check nginx, so don't even try.
	 * The only way to be absolutely sure is to exploit it :)
	 */
	static Pattern openSSLversionPattern = Pattern.compile ("Server:.*?(OpenSSL/([0-9.]+[a-z-]+))", Pattern.CASE_INSENSITIVE);
	
	/**
	 * vulnerable versions, courtesy of http://cvedetails.com/cve-details.php?t=1&cve_id=CVE-2014-0160
	 */
	
	static String [] openSSLvulnerableVersions = {
		"1.0.1-Beta1",
		"1.0.1-Beta2",
		"1.0.1-Beta3",
		"1.0.1", 
		"1.0.1a", 
		"1.0.1b", 
		"1.0.1c", 
		"1.0.1d", 
		"1.0.1e", 
		"1.0.1f", 
		"1.0.2-beta"  //does not come from the page above, but reported elsewhere to be vulnerable. 
		};
	
	/**
	 * Prefix for internationalized messages used by this rule
	 */
	private static final String MESSAGE_PREFIX = "pscanalpha.heartbleed.";

	/**
	 * gets the name of the scanner
	 * @return
	 */
	@Override
	public String getName() {
		return Constant.messages.getString(MESSAGE_PREFIX + "name");
	}

	/**
	 * scans the HTTP request sent (in fact, does nothing)
	 * @param msg
	 * @param id
	 */
	@Override
	public void scanHttpRequestSend(HttpMessage msg, int id) {
		// do nothing
	}

	/**
	 * scans the HTTP response for signatures that might indicate the Heartbleed OpenSSL vulnerability 
	 * @param msg
	 * @param id
	 * @param source unused
	 */
	@Override
	public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
		//get the body contents as a String, so we can match against it
		String responseheaders = msg.getResponseHeader().getHeadersAsString();
				
		String versionNumber = null;
		String openSSLfullVersionString = null;
		Matcher matcher = openSSLversionPattern.matcher(responseheaders);
        if (matcher.find()) {
        	openSSLfullVersionString =  matcher.group(1);  //get the OpenSSL/1.0.1e string
            versionNumber = matcher.group(2);  //get the sub-match, since this contains the version details..
        } 
       
		if (versionNumber!=null && versionNumber.length() > 0) {
			//if the version matches any of the known vulnerable versions, raise an alert.
			for (int i = 0; i < openSSLvulnerableVersions.length; i ++) {
				if (versionNumber.equalsIgnoreCase(openSSLvulnerableVersions[i])) {
					//Suspicious, but not a warning, because the reported version could have a security back-port.
					Alert alert = new Alert(getPluginId(), Alert.RISK_HIGH, Alert.CONFIDENCE_LOW, getName());
					     
					alert.setDetail(
							getDescription(),  
							msg.getRequestHeader().getURI().toString(), 
							"", //param
							"", //attack 
							getExtraInfo(msg, openSSLfullVersionString),  //other info
							getSolution(),
							getReference(), 
							openSSLfullVersionString,	
							119,	//CWE 119: Failure to Constrain Operations within the Bounds of a Memory Buffer
							20,		//WASC-20: Improper Input Handling
							msg);  
					parent.raiseAlert(id, alert);
					return;
				}
			}
		}
	}

	/**
	 * sets the parent
	 * @param parent
	 */
	@Override
	public void setParent(PassiveScanThread parent) {
		this.parent = parent;
	}

	/**
	 * get the id of the scanner
	 * @return
	 */
	@Override
	public int getPluginId() {
		return 10034;
	}

	/**
	 * get the description of the alert
	 * @return
	 */
	private String getDescription() {
		return Constant.messages.getString(MESSAGE_PREFIX + "desc");
	}

	/**
	 * get the solution for the alert
	 * @return
	 */
	private String getSolution() {
		return Constant.messages.getString(MESSAGE_PREFIX + "soln");
	}

	/**
	 * gets references for the alert
	 * @return
	 */
	private String getReference() {
		return Constant.messages.getString(MESSAGE_PREFIX + "refs");
	}

	/**
	 * gets extra information associated with the alert
	 * @param msg
	 * @param arg0
	 * @return
	 */
	private String getExtraInfo(HttpMessage msg, String arg0) {		
		return Constant.messages.getString(MESSAGE_PREFIX + "extrainfo", arg0);        
	}

}

