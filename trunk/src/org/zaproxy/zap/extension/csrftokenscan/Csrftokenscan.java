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
package org.zaproxy.zap.extension.csrftokenscan;

import java.io.IOException;
import java.io.StringReader;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.MissingResourceException;
import java.util.ResourceBundle;
import java.util.TreeSet;
import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.HTMLElementName;
import net.htmlparser.jericho.Source;
import org.apache.log4j.Level;
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

	private ResourceBundle messages = ResourceBundle.getBundle(this.getClass()
			.getPackage().getName()
			+ ".Messages", Constant.getLocale());

	/**
     * Constructor of the class, sets the logging level
     */
	public Csrftokenscan() {
		this.log.setLevel(Level.ALL);
	}

	/**
	 * @return the Id of the plugin
	 */
	public int getId() {
		return 20012;
	}

	/**
	 * @return the name of the plugin
	 */
	public String getName() {
		return "Anti CSRF tokens scanner";
	}

	/**
	 * @return dependencies of the plugin (none)
	 */
	public String[] getDependency() {
		return null;
	}

	/**
	 * @return the description of the vulnerability
	 */
	public String getDescription() {
		if (vuln != null) {
			return vuln.getDescription();
		}
		return "Failed to load vulnerability description from file";
	}

	/**
	 * @return the category of the vulnerability (Server side).
	 */
	public int getCategory() {
		return Category.SERVER;
	}

	/**
	 * @return The solution of the vulnerability
	 */
	public String getSolution() {
		if (vuln != null) {
			return vuln.getSolution();
		}
		return "Failed to load vulnerability solution from file";
	}

	/**
	 * @return Reference for more information about the vulnerability
	 */
	public String getReference() {
		if (vuln != null) {
			StringBuffer sb = new StringBuffer();
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
	public void init() {

	}

	/**
	 * Main  method of the class. It is executed for each page.
	 * Determined whether the page in vulnerable to CSRF or not.
	 */
	@Override
	public void scan() {

		boolean vuln = false;
		Map<String, String> tagsMap = new HashMap<String, String>();
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
					if (element.getAttributeValue("type").toLowerCase().equals("hidden")) {
						tagsMap.put(element.getAttributeValue("name"), element.getAttributeValue("value"));
						log.debug("Input Tag: " + element.getAttributeValue("name") + ", " + element.getAttributeValue("value"));
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
					if (element2.getAttributeValue("type").toLowerCase().equals("hidden")) {
						
						// If the values of the tags changed they are an anti-csrf token
						if (!tagsMap.get(element2.getAttributeValue("name"))
								.equals(element2.getAttributeValue("value"))) {
							log.debug("Found Anti-CSRF token: "
									+ element2.getAttributeValue("name") + ", "
									+ element2.getAttributeValue("value"));
							vuln = false;
						}
					}
				}
				// If vulnerable, generates the alert
				if (vuln) {
					String desc = this.getString("noanticsrftokens.desc");
					String attack = this.getString("noanticsrftokens.alert.attack");
					String extraInfo = this.getString("noanticsrftokens.alert.extrainfo");
					bingo(Alert.RISK_HIGH, Alert.WARNING, attack, desc,
							getBaseMsg().getRequestHeader().getURI().getURI(),
							getReference(), attack, extraInfo, getSolution(),
							getBaseMsg());
				}
			}
		} catch (IOException e) {
			log.error(e);
		}
	}

	/**
	 * 
	 * @param key
	 * @return the value of the given key
	 */
	public String getString(String key) {
		try {
			return messages.getString(key);
		} catch (MissingResourceException e) {
			return '!' + key + '!';
		}
	}

	@Override
	public int getRisk() {
		return Alert.RISK_HIGH;
	}

}