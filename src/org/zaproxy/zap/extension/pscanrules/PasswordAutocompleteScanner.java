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

import java.util.Date;
import java.util.List;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.HTMLElementName;
import net.htmlparser.jericho.Source;


public class PasswordAutocompleteScanner extends PluginPassiveScanner {

	/**
	 * Prefix for internationalised messages used by this rule
	 */
	private static final String MESSAGE_PREFIX = "pscanrules.passwordautocompletescanner.";
	private static final int PLUGIN_ID = 10012;
	
	private PassiveScanThread parent = null;
	private Logger logger = Logger.getLogger(this.getClass());

	@Override
	public void setParent (PassiveScanThread parent) {
		this.parent = parent;
	}

	@Override
	public void scanHttpRequestSend(HttpMessage msg, int id) {
		// Ignore
	}

	@Override
	public int getPluginId() {
		return PLUGIN_ID;
	}

	@Override
	public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
		Date start = new Date();
		
		List<Element> formElements = source.getAllElements(HTMLElementName.FORM);
		
		if (formElements != null && formElements.size() > 0) {
			// Loop through all of the FORM tags
			logger.debug("Found " + formElements.size() + " forms");
			
			for (Element formElement : formElements) {
				String autoComplete = formElement.getAttributeValue("AUTOCOMPLETE");
				
				if (autoComplete == null || ! autoComplete.equalsIgnoreCase("OFF")) {
					// The form doesnt have autocomplete turned to off
					List<Element> inputElements = formElement.getAllElements(HTMLElementName.INPUT);
					
					if (inputElements != null && inputElements.size() > 0) {
						// Loop through all of the INPUT elements
						logger.debug("Found " + inputElements.size() + " inputs");
						for (Element inputElement : inputElements) {
							String type = inputElement.getAttributeValue("TYPE");
							if (type != null && type.equalsIgnoreCase("PASSWORD")) {
								
								autoComplete = inputElement.getAttributeValue("AUTOCOMPLETE");
								if (autoComplete == null || ! autoComplete.equalsIgnoreCase("OFF")) {
									String param = inputElement.getName();
									if (inputElement.getAttributeValue("id") != null) {
										param = inputElement.getAttributeValue("id");
									} else if (inputElement.getAttributeValue("name") != null) {
										param = inputElement.getAttributeValue("name");
									}
									
									Alert alert = new Alert(getPluginId(), Alert.RISK_LOW, Alert.CONFIDENCE_MEDIUM, 
										getName());
										alert.setDetail(
											getDescription(), //Description
											msg.getRequestHeader().getURI().toString(),//URI
											param,
											"", //Attack
											"", //OtherInfo
											getSolution(), //Solution
											getReference(), //Refs
											inputElement.toString(), // Evidence - the relevant element
								            525,	// CWE Id
								            15,	// WASC Id 15 - Application Misconfiguration
											msg);
									
									parent.raiseAlert(id, alert);
								}
							}
						}
					}
				}
			}
		}
		if (logger.isDebugEnabled()) {
			logger.debug("\tScan of record " + id + " took " + ((new Date()).getTime() - start.getTime()) + " ms");
		}
		
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
