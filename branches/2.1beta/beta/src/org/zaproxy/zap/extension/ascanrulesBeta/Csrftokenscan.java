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

import java.io.IOException;
import java.io.StringReader;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.HTMLElementName;
import net.htmlparser.jericho.Source;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.model.Vulnerabilities;
import org.zaproxy.zap.model.Vulnerability;

/**
 * Csrftokenscan is an effort to improve the anti-CSRF token detection of ZAP
 * It is based on previous plugins such as csrfcountermeasuresscan and sessionfixation
 */
public class Csrftokenscan extends AbstractAppPlugin {

	// WASC Threat Classification (WASC-9)
	private static Vulnerability vuln = Vulnerabilities.getVulnerability("wasc_9");

	private static Logger log = Logger.getLogger(Csrftokenscan.class);

	/**
     * Constructor of the class, sets the logging level
     */
	public Csrftokenscan() {
		AscanUtils.registerI18N();
	}

	/**
	 * @return the Id of the plugin
	 */
	@Override
	public int getId() {
		return 20012;
	}

	/**
	 * @return the name of the plugin
	 */
	@Override
	public String getName() {
		return "Anti CSRF tokens scanner";
	}

	/**
	 * @return dependencies of the plugin (none)
	 */
	@Override
	public String[] getDependency() {
		return null;
	}

	/**
	 * @return the description of the vulnerability
	 */
	@Override
	public String getDescription() {
		if (vuln != null) {
			return vuln.getDescription();
		}
		return "Failed to load vulnerability description from file";
	}

	/**
	 * @return the category of the vulnerability (Server side).
	 */
	@Override
	public int getCategory() {
		return Category.SERVER;
	}

	/**
	 * @return The solution of the vulnerability
	 */
	@Override
	public String getSolution() {
		if (vuln != null) {
			return vuln.getSolution();
		}
		return "Failed to load vulnerability solution from file";
	}

	/**
	 * @return Reference for more information about the vulnerability
	 */
	@Override
	public String getReference() {
		if (vuln != null) {
			StringBuilder sb = new StringBuilder();
			for (String ref : vuln.getReferences()) {
				if (sb.length() > 0) {
					sb.append("\n");
				}
				sb.append(ref);
			}
			return sb.toString();
		}
		return "Failed to load vulnerability reference from file";
	}

	/**
	 * 
	 */
	@Override
	public void init() {

	}

	/**
	 * Main  method of the class. It is executed for each page.
	 * Determined whether the page in vulnerable to CSRF or not.
	 */
	@Override
	public void scan() {

		boolean vuln = false;
		Map<String, String> tagsMap = new HashMap<>();
		Source s;
		try {		
			// We parse the HTML of the response
			s = new Source(new StringReader(getBaseMsg().getResponseBody().toString()));

			/* If the page has input fields, it performs a potential critical
			 * action and it will be vulnerable to CSRF if not proved otherwise*/
			if (!s.getAllElements(HTMLElementName.INPUT).isEmpty()) {
				vuln = true;
				log.debug("The page has parameters marked temporary vulnerable");
			
				// We store the hidden input fields in a hash map.
				List<Element> iElements = s.getAllElements(HTMLElementName.INPUT);
				for (Element element : iElements) {
					if (isHiddenInputElement(element) && hasNameAttribute(element)) {
						final String name = element.getAttributeValue("name");
						final String value = getNonNullValueAttribute(element);
						tagsMap.put(name, value);
						log.debug("Input Tag: " + name + ", " + value);
					}
				}
	
				// We clean up the cookies and perform again the request
				HttpMessage newMsg = getNewMsg();
				newMsg.setCookieParams(new TreeSet<HtmlParameter>());
				sendAndReceive(newMsg);
	
				// We parse the HTML of the response
				s = new Source(new StringReader(newMsg.getResponseBody().toString()));
				iElements = s.getAllElements(HTMLElementName.INPUT);
	
				// We store the hidden input fields in a hash map.
				for (Element element2 : iElements) {
					if (isHiddenInputElement(element2) && hasNameAttribute(element2)) {
						final String name = element2.getAttributeValue("name");
						final String newValue = getNonNullValueAttribute(element2);
						final String oldValue = tagsMap.get(name);
						if (oldValue != null && !newValue.equals(oldValue)) {
							log.debug("Found Anti-CSRF token: " + name + ", " + newValue);
							vuln = false;
						}
					}
				}
				// If vulnerable, generates the alert
				if (vuln) {
					// TODO attack should probably be the relevant FORM tag 
					String attack = Constant.messages.getString("ascanbeta.noanticsrftokens.alert.attack");
					String extraInfo = Constant.messages.getString("ascanbeta.noanticsrftokens.alert.extrainfo");
					bingo(Alert.RISK_HIGH, Alert.WARNING, 
							null,
							attack, extraInfo, getSolution(),
							getBaseMsg());
				}
			}
		} catch (IOException e) {
			log.error(e);
		}
	}

    private static boolean isHiddenInputElement(Element inputElement) {
        return "hidden".equalsIgnoreCase(inputElement.getAttributeValue("type"));
    }

    private static boolean hasNameAttribute(Element element) {
        return element.getAttributeValue("name") != null;
    }

    private static String getNonNullValueAttribute(Element element) {
        final String value = element.getAttributeValue("value");

        if (value == null) {
            return "";
        }
        return value;
    }

	@Override
	public int getRisk() {
		return Alert.RISK_HIGH;
	}

}