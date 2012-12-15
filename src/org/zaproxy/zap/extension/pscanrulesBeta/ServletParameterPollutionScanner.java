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

import java.util.Iterator;
import java.util.List;

import net.htmlparser.jericho.Attribute;
import net.htmlparser.jericho.Attributes;
import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.HTMLElementName;
import net.htmlparser.jericho.Source;

import org.apache.log4j.Logger;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/**
 * Servlet Parameter Pollution rule.
 * Suggested by Jeff Williams on the OWASP Leaders List: 
 * http://lists.owasp.org/pipermail/owasp-leaders/2012-July/007521.html
 * @author psiinon
 *
 */
public class ServletParameterPollutionScanner extends PluginPassiveScanner {

	private PassiveScanThread parent = null;
	private static final Logger logger = Logger.getLogger(ServletParameterPollutionScanner.class);

	@Override
	public void setParent (PassiveScanThread parent) {
		this.parent = parent;
	}

	@Override
	public void scanHttpRequestSend(HttpMessage msg, int id) {
		// Ignore
	}

	private int getId() {
		return 10026;
	}

	@Override
	public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
		List<Element> formElements = source.getAllElements(HTMLElementName.FORM);
		
		if (formElements != null && formElements.size() > 0) {			
			// Loop through all of the FORM tags
			logger.debug("Found " + formElements.size() + " forms");
			
			// check for 'target' param
			
			for (Element formElement : formElements) {
				boolean actionFound = false;
				Attributes atts = formElement.getAttributes();
				Iterator<Attribute> iter = atts.iterator();
				
				while (iter.hasNext()) {
					Attribute att = iter.next();
					if (att.getName().equalsIgnoreCase("action") && att.getValue().length() > 0) {
						// action tag present (and with a value), so should be ok
						actionFound = true;
					}
				}
				
				if (!actionFound) {
				    Alert alert = new Alert(getId(), Alert.RISK_MEDIUM, Alert.SUSPICIOUS, 
					    	getName());
					    	alert.setDetail(
					    		getDescription(), 
					    		msg.getRequestHeader().getURI().toString(),
					    		"", 
					    		"", 
					    		"",
					    		getSolution(), 
					            getReference(), 
					            msg);

				    parent.raiseAlert(id, alert);
				    // Only raise one alert per page
				    return;
				}
			}

		}
	}

	@Override
	public String getName() {
    	return "HTTP Parameter Override";
	}
	
    public String getDescription() {
    	return "Unspecified form target: HTTP parameter override attack potentially possible.\n" +
    			"This is a known problem with Java Servlets but other platforms way also be vulnerable.";
    }

    public int getCategory() {
        return Category.MISC;
    }

    public String getSolution() {
    	return "All forms must specify the action URL";
    }

    public String getReference() {
    	return "http://java.net/attachments/lists/servlet-spec/jsr340-experts/2012-06/15/OnParameterPollutionAttacks.pdf";
    }

}
