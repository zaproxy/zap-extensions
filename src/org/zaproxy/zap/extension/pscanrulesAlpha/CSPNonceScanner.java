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

package org.zaproxy.zap.extension.pscanrulesAlpha;

import java.util.List;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Vector;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.HTMLElementName;
import net.htmlparser.jericho.Source;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/**
 * Invalid CSP Nonce passive scan rule
 *
 * @author
 */
public class CSPNonceScanner extends PluginPassiveScanner{

	private static final String MESSAGE_PREFIX = "pscanalpha.cspnonce.";
	private static final int PLUGIN_ID = 19999; // TODO: get assigned an ID
	private static final String CSP_HEADER = "Content-Security-Policy";

	// https://w3c.github.io/webappsec-csp/#grammardef-nonce-source
	private static final Pattern NONCE_SRC_PATT = Pattern.compile("nonce-([^ ,;]*)");
	private static final Pattern VALID_NONCE_PATT = Pattern.compile("[A-Za-z0-9+/-_]+=?=?");

	private enum VulnType {CSP_NONCE_REUSED, CSP_INVALID_NONCE};

	private PassiveScanThread parent = null;
	private static final Logger logger = Logger.getLogger(CSPNonceScanner.class);

	// nonce-srcs seen in responses
	private HashSet<String> Nonces = new HashSet<String>();

	@Override
	public void setParent(PassiveScanThread parent) {
		this.parent = parent;
	}

	@Override
	public void scanHttpRequestSend(HttpMessage msg, int id) {
		// Only checking the response for this plugin
	}

	private void raiseAlert(VulnType currentVT, String evidence, HttpMessage msg, int id) {
		Alert alert = new Alert(getPluginId(), //PluginID
					getRisk(currentVT),
					Alert.CONFIDENCE_HIGH, //Reliability
					getAlertElement(currentVT, "name")); //Name
			alert.setDetail(
				getAlertElement(currentVT, "desc"), //Description
				msg.getRequestHeader().getURI().toString(), //URI
				"",	// Param
				"", // Attack
				"", // Other info
				getAlertElement(currentVT, "soln"), //Solution
				getAlertElement(currentVT, "refs"), //References
				evidence,	// Evidence
					16, // CWE-16: Configuration
					15,	//WASC-15: Application Misconfiguration
				msg); //HttpMessage
			parent.raiseAlert(id, alert);
	}

	private boolean isNonceSrcValid(String nonceSrc) {
		Matcher validNonceMatcher = VALID_NONCE_PATT.matcher(nonceSrc);
		return validNonceMatcher.matches();
	}

	private List<String> getNonceSrcs(String header) {
		List<String> nonceSrcs = new ArrayList<String>();
		Matcher nonceSrcMatcher = NONCE_SRC_PATT.matcher(header);

		while (nonceSrcMatcher.find()) {
			nonceSrcs.add(nonceSrcMatcher.group(1));
		}
		return nonceSrcs;
	}

	private void checkNonces(HttpMessage msg, int id, String header) {
		for (String nonceSrc: getNonceSrcs(header)) {
			if (!isNonceSrcValid(nonceSrc)) {
				raiseAlert(VulnType.CSP_INVALID_NONCE, nonceSrc, msg, id);
			}
			if (Nonces.contains(nonceSrc)) {
				raiseAlert(VulnType.CSP_NONCE_REUSED, nonceSrc, msg, id);
			}
			Nonces.add(nonceSrc);
		}
	}

	@Override
	public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
		long start = System.currentTimeMillis();
		Vector<String> cspHeaders = msg.getResponseHeader().getHeaders(CSP_HEADER);
		List<String> metaCSPHeaders = getMetaCSPContent(source);

		// Check CSP HTTP Response Headers
		if (cspHeaders != null) {
			for (String header: cspHeaders) {
				checkNonces(msg, id, header);
			}
		}

		// Check meta http-equiv CSP content
		for (String header: metaCSPHeaders) {
			checkNonces(msg, id, header);
		}

		if (logger.isDebugEnabled()) {
			logger.debug("\tScan of record " + id + " took " + (System.currentTimeMillis() - start) + " ms");
		}
	}

	@Override
	public int getPluginId() {
		return PLUGIN_ID;
	}

	@Override
	public String getName() {
		return Constant.messages.getString(MESSAGE_PREFIX + "scanner.name");
	}

	private String getAlertElement(VulnType currentVT, String element) {
		String elementValue="";
		switch (currentVT) {
			case CSP_INVALID_NONCE:
				elementValue=Constant.messages.getString(MESSAGE_PREFIX + element);
				break;
			case CSP_NONCE_REUSED:
				elementValue=Constant.messages.getString(MESSAGE_PREFIX + element);
				break;
		}
		return elementValue;
	}

	private int getRisk(VulnType currentVT) {
		switch (currentVT) {
			case CSP_INVALID_NONCE:
			case CSP_NONCE_REUSED:
			default:
				return Alert.RISK_INFO;
		}
	}

	/**
	 * Get a CSP content from META http-equiv tags.
	 *
	 * @param source the source of the response to be analyzed.
	 * @return returns the content attribute from meta
	 * elements with http-equiv="Content-Security-Policy" as a
	 * {@code List<String>}, which is empty when nonce are found.
	 * @see <a href="https://w3c.github.io/webappsec-csp/#meta-element"> CSP Section 3.3</a>
	 */
	private List<String> getMetaCSPContent(Source source) {
		List<Element> metaElements = source.getAllElements(HTMLElementName.META);
		String httpEquiv;
		List<String> cspContents = new ArrayList<String>();

		if (metaElements != null) {
			for (Element metaElement: metaElements) {
				httpEquiv = metaElement.getAttributeValue("http-equiv");

				if (CSP_HEADER.equalsIgnoreCase(httpEquiv)) {
					cspContents.add(metaElement.getAttributeValue("content"));
				}
			}
		}
		return cspContents;
	}
}
