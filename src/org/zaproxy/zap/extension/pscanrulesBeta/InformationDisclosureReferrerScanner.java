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
package org.zaproxy.zap.extension.pscanrulesBeta;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Vector;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import net.htmlparser.jericho.Source;

import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

public class InformationDisclosureReferrerScanner extends PluginPassiveScanner {

	private PassiveScanThread parent = null;
	private static final String URLSensitiveInformationFile = "xml/URL-information-disclosure-messages.txt";
	private static final Logger logger = Logger.getLogger(InformationDisclosureReferrerScanner.class);
	private List<String> messages = null;
	
	@Override
	public void scanHttpRequestSend(HttpMessage msg, int id) {
		if (msg.getRequestHeader().getHeader(HttpHeader.REFERER) != null && !isRequestedURLSameDomainAsHTTPReferrer(msg.getRequestHeader().getHostName(), msg.getRequestHeader().getHeader(HttpHeader.REFERER))) {
			Vector<String> referrer = msg.getRequestHeader().getHeaders(HttpHeader.REFERER);
			String evidence;
			for (String referrerValue : referrer) {
				if ((evidence = doesURLContainsSensitiveInformation(referrerValue)) != null) {
					this.raiseAlert(msg, id, evidence, "The URL in the referrer appears to contain sensitive infomation");
				}
				if ((evidence = doesContainCreditCard(referrerValue)) != null) {
					this.raiseAlert(msg, id, evidence, "The URL in the referrer appears to contain credit card information");
				}
				if ((evidence = doesContainEmailAddress(referrerValue)) != null) {
					this.raiseAlert(msg, id, evidence, "The URL in the referrer contains email address(es)");
				}
				if ((evidence = doesContainUsSSN(referrerValue)) != null) {
					this.raiseAlert(msg, id, evidence, "The URL in the referrer appears to contain US Social Security Number(s)");
				}	
			}
		}
	}
	
	private boolean isRequestedURLSameDomainAsHTTPReferrer (String host, String referrerURL){
		boolean result = false;
		if(referrerURL.startsWith("/")){
			result = true;
		} else {
			try {
				URI referrerURI = new URI(referrerURL, true);	
				if(referrerURI.getHost() != null && referrerURI.getHost().toLowerCase().equals(host.toLowerCase())){
					result = true;
				}
			} catch (URIException e) {
				logger.debug("Error: " + e.getMessage());
			}
		}
		return result;
	}
	
	private void raiseAlert(HttpMessage msg, int id, String evidence, String other) {
		Alert alert = new Alert(getPluginId(), Alert.RISK_INFO, Alert.WARNING, 
		    	getName());
		    	alert.setDetail(
		    			"The HTTP Header may have leaked a potentially sensitive parameter to another domain. This can violate PCI and most organizational compliance policies. You can configure the list of strings for this check to add or remove values specific to your environment", 
		    	    msg.getRequestHeader().getURI().toString(),
		    	    "",
		    	    "", 
		    	    other,
		    	    "Do not pass sensitive information in URI's", 
		            "", 
					evidence,	// Evidence
					0,	// TODO CWE Id
		            13,	// WASC Id - Info leakage
		            msg);
	
    	parent.raiseAlert(id, alert);
	}
	
	private List<String> loadFile(String file) {
		List<String> strings = new ArrayList<String>();
		BufferedReader reader = null;
		File f = new File(Constant.getZapHome() + File.separator + file);
		if (! f.exists()) {
			logger.error("No such file: " + f.getAbsolutePath());
			return strings;
		}
		try {
			String line;
			reader = new BufferedReader(new FileReader(f));
			while ((line = reader.readLine()) != null) {
				if (!line.startsWith("#")) {
					strings.add(line.trim().toLowerCase());
				}
			}
		} catch (IOException e) {
			logger.debug("Error on opening/reading debug error file. Error: " + e.getMessage(), e);
		} finally {
			if (reader != null) {
				try {
					reader.close();			
				}
				catch (IOException e) {
					logger.debug("Error on closing the file reader. Error: " + e.getMessage(), e);
				}
			}
		}
		return strings;
	}

	
	private String doesURLContainsSensitiveInformation (String url) {
		if (this.messages == null) {
			this.messages = loadFile(URLSensitiveInformationFile);
		}
		String lcUrl = url.toLowerCase();
		for (String msg : this.messages) {
			int start = lcUrl.indexOf(msg);
			if (start >= 0) {
				// Return the original (case exact) string so we can match it in the response
				return url.substring(start, start + msg.length());
			}
		}
		return null;
	}

	@Override
	public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {

	}

	@Override
	public int getPluginId() {
		return 10025;
	}
	
	@Override
	public void setParent(PassiveScanThread parent) {
		this.parent = parent;
	}

	@Override
	public String getName() {
		return "Information Disclosure - Sensitive Information in HTTP Referrer Header";
	}
	
	private String doesContainEmailAddress(String emailAddress) {
		Pattern emailAddressPattern = Pattern.compile("\\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,4}\\b");
		Matcher matcher = emailAddressPattern.matcher(emailAddress);
		if (matcher.find()) {
			return matcher.group();
		}
		return null;
	}
	
	private String doesContainCreditCard(String creditCard) {
		Pattern creditCardPattern = Pattern.compile("\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\\d{3})\\d{11})\\b");
		Matcher matcher = creditCardPattern.matcher(creditCard);
		if (matcher.find()) {
			return matcher.group();
		}
		return null;
	}
	
	private String doesContainUsSSN(String usSSN) {
		Pattern usSSNPattern = Pattern.compile("\\b[0-9]{3}-[0-9]{2}-[0-9]{4}\\b");
		Matcher matcher = usSSNPattern.matcher(usSSN);
		if (matcher.find()){
			return matcher.group();
		}
		return null;
	}
}
