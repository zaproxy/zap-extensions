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

import org.apache.commons.httpclient.URIException;
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
	private final double DISTANCE_RATIO_THRESHOLD = 0.5;

	private ResourceBundle messages = ResourceBundle.getBundle(this.getClass()
			.getPackage().getName()
			+ ".Messages", Constant.getLocale());

	/**
     * Constructor of the class, sets the logging level
     */
	public Csrftokenscan() {
		this.log.setLevel(org.apache.log4j.Level.ALL);
	}

	/**
	 * @return the Id of the plugin
	 */
	@Override
	public int getId() {
		return 20012;
	}
	@Override
    public Level getLevel(boolean incDefault) {
		return Level.HIGH;
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
		return this.getString("noanticsrftokens.desc");
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
		return this.getString("noanticsrftokens.alert.sol");
	}
	
	/**
	 * @return Reference for more information about the vulnerability
	 */
	@Override
	public String getReference() {
		return this.getString("noanticsrftokens.alert.extrainfo");
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

				// Check if the page requires authentication
				if (this.isStatusOk(getBaseMsg(),newMsg)) {
					// We parse the HTML of the response
					s = new Source(new StringReader(newMsg.getResponseBody().toString()));
					iElements = s.getAllElements(HTMLElementName.INPUT);
		
					// We store the hidden input fields in a hash map.
					for (Element element2 : iElements) {
						if (element2.getAttributeValue("type").toLowerCase().equals("hidden")) {
	
							// If the values of the tags changed and are random enough: they are an anti-csrf token
							if (!tagsMap.get(element2.getAttributeValue("name"))
									.equals(element2.getAttributeValue("value"))
									&& this.isRandom(tagsMap.get(element2
											.getAttributeValue("name")), element2
											.getAttributeValue("value")) &&
											!isSessionId(getBaseMsg(), element2.getAttributeValue("value"))) {
								log.debug("Found Anti-CSRF token: "
										+ element2.getAttributeValue("name") + ", "
										+ element2.getAttributeValue("value"));
								vuln = false;
							}
						}
					}
			}
				// If vulnerable, generates the alert
				if (vuln) {
					String params ="";
					for (Element element2 : iElements) {
						params=params + "[" + element2.getAttributeValue("name") + ":" + element2.getAttributeValue("value")+"], ";
					}
					this.generateReport(params);
				}
			}
		} catch (IOException e) {
			log.error(e);
		}
	}
	
	/**
	 * 
	 * @param m1 first httpmessage
	 * @param m2 second httpmessage
	 * @return if the second request were successful
	 */
	private boolean isStatusOk(HttpMessage m1, HttpMessage m2) {
		/* if the status code of the response is the same in both of the requests 
		 * or the new one is not a 3XX we are good */
		if (m1.getResponseHeader().getStatusCode() == m2.getResponseHeader().getStatusCode() ||
				!String.valueOf(m2.getResponseHeader().getStatusCode()).startsWith("3")) {
			return true;
		} else {
			return false;
		}
	}
	
	
	/**
	 * 
	 * @param str1 first token to compare
	 * @param str2 second token to compare
	 * @return true if the randomness estimation seems good, false otherwise
	 */
	private boolean isRandom(String str1, String str2) {
		int[][] distance = new int[str1.length() + 1][str2.length() + 1];

		for (int i = 0; i <= str1.length(); i++)
			distance[i][0] = i;
		for (int j = 1; j <= str2.length(); j++)
			distance[0][j] = j;

		for (int i = 1; i <= str1.length(); i++)
			for (int j = 1; j <= str2.length(); j++)
				distance[i][j] = minimum(
						distance[i - 1][j] + 1,
						distance[i][j - 1] + 1,
						distance[i - 1][j - 1]
								+ ((str1.charAt(i - 1) == str2.charAt(j - 1)) ? 0
										: 1));
		int dist = distance[str1.length()][str2.length()];
		double ratio = ((double) distance[str1.length()][str2.length()] / (Math
				.max(str1.length(), str2.length())));
		log.debug("the distance between \"" + str1 + "\" and \"" + str2
				+ "\" is " + dist + " and their ratio is: " + ratio);
		if (((double) ratio) > this.DISTANCE_RATIO_THRESHOLD) {
			log.debug("The distance between \"" + str1 + "\" and \"" + str2
					+ "\" is " + dist + " and their ratio is: " + ratio
					+ ", random enough");
			return true;
		} else {
			log.debug("The distance between \"" + str1 + "\" and \"" + str2
					+ "\" is " + dist + " and their ratio is: " + ratio
					+ ", BAD randomness");
			return false;
		}
	}
	
	/**
	 * 
	 * @param m the initial HttpMessage
	 * @param s the potential anti-csrf token
	 * @return if s is the session id
	 */
	private boolean isSessionId(HttpMessage m, String s) {
		if(m.getCookieParamsAsString().contains(s)) {
			return true;
		} else {
			return false;
		}
	}
	
	/**
	 * 
	 * @param vulnLinks list of the vulnerable links in the page
	 */
	public void generateReport( String params) {

		log.debug("Page vulnerable to CSRF attacks");
		String attack = this.getString("noanticsrftokens.name");
		try {
			bingo(Alert.RISK_HIGH, Alert.WARNING, attack, this.getDescription(), getBaseMsg().getRequestHeader().getURI().getURI(), params, attack, "Affected parameters: "+params, this.getSolution(), this.getBaseMsg());
		} catch (URIException e) {
			log.error(e);
		}
	}
	
	/**
	 * 
	 * @param a integer to compare
	 * @param b integer to compare
	 * @param c integer to compare
	 * @return minimum integer
	 */
	private static int minimum(int a, int b, int c) {
		return Math.min(Math.min(a, b), c);
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


}