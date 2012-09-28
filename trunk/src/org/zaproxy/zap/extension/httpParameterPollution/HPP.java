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

package org.zaproxy.zap.extension.httpParameterPollution;

import java.io.StringReader;
import java.util.ArrayList;
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
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpMessage;

/**
 * HPP is an effort to improve the anti-CSRF token detection of ZAP It is based
 * on previous plugins such as csrfcountermeasuresscan and sessionfixation
 */
public class HPP extends AbstractAppPlugin {

	private static Logger log = Logger.getLogger(HPP.class);
	private ResourceBundle messages = ResourceBundle.getBundle(this.getClass().getPackage().getName() + ".Messages", Constant.getLocale());
	private final String payload = "%26zap%3Dzaproxy";

	
	/**
	 * Constructor of the class, sets the logging level
	 */
	public HPP() {
		//log.setLevel(Level.ALL); //uncomment this for debugging
	}

	
	/**
	 * @return the Id of the plugin
	 */
	@Override
	public int getId() {
		return 20014;
	}

	
	/**
	 * @return the name of the plugin
	 */
	@Override
	public String getName() {
		return this.getString("HTTPParamPoll.name");
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
		return this.getString("HTTPParamPoll.desc");
	}

	
	/**
	 * @return the category of the vulnerability (INJECTION).
	 */
	@Override
	public int getCategory() {
		return Category.INJECTION;
	}

	
	/**
	 * @return The solution of the vulnerability
	 */
	@Override
	public String getSolution() {
		return this.getString("HTTPParamPoll.sol");
	}

	
	/**
	 * @return Reference for more information about the vulnerability
	 */
	@Override
	public String getReference() {
		return this.getString("HTTPParamPoll.extrainfo");
	}

	
	/**
	 * 
	 */
	@Override
	public void init() {

	}
	

	/**
	 * Main method of the class. It is executed for each page. Determined
	 * whether the page in vulnerable to HPP or not.
	 */
	@Override
	public void scan() {

		try {
			log.debug("Targeting " + getBaseMsg().getRequestHeader().getURI());

			// pages are not vulnerable if not proved otherwise
			List<String> vulnLinks = new ArrayList<String>();

			// We parse the HTML of the response and get all its parameters
			Source s = new Source(new StringReader(getBaseMsg().getResponseBody().toString()));
			List<Element> inputTags = s.getAllElements(HTMLElementName.INPUT);
			TreeSet<HtmlParameter> tags = this.getParams(s, inputTags);
			
			/* If there are input fields, they can potentially be polluted */
			if (!inputTags.isEmpty()) {
				if(!tags.isEmpty()) {
					
					// We send the request with the injected payload in the parameters
					log.debug("Injecting payload...");
					HttpMessage newMsg = getNewMsg();
					newMsg.setGetParams(tags);
					sendAndReceive(newMsg);
					
					// We check all the links of the response to find our payload
					s = new Source(new StringReader(newMsg.getResponseBody().toString()));
					List<Element> links = s.getAllElements(HTMLElementName.A);
					if (!links.isEmpty()) {
						vulnLinks = this.findPayload(s, inputTags, vulnLinks);
						
						// If vulnerable, generates the alert
						if (!vulnLinks.isEmpty()) {
							this.GenerateReport(vulnLinks);
						}
					}
				}
			}
			if(vulnLinks.isEmpty()) {
				log.debug("Page not vulnerable to HPP attacks");
			}
		} catch (Exception e) {
			log.error(e);
		}
	}
	
	
	/**
	 * 
	 * @param s the source code of the targeted page
	 * @param inputTags list of input parameters
	 * @param vulnLinks empty list of the vulnerable links in the page
	 * @return filled list of the vulnerable links in the page
	 */
	public List<String> findPayload(Source s, List<Element> inputTags, List<String> vulnLinks) {
		//TODO: we should consider other tags besides <a>
		List<Element> links = s.getAllElements(HTMLElementName.A);
		for (Element link : links) {
			for (Element tag : inputTags) {
				Map<String, List<String>> map = getUrlParameters(link.getAttributeValue("href"));
				if (map.get(tag.getAttributeValue("name")) != null) {
					if (map.get(tag.getAttributeValue("name")).contains(this.payload)) {
						log.debug("Found Vulnerable Parameter with the injected payload: " + tag.getAttributeValue("name")+ ", "+ map.get(tag.getAttributeValue("name")));
						vulnLinks.add(tag.getAttributeValue("name")+ ", "+ map.get(tag.getAttributeValue("name")));
					}
				}
			}
		}
		return vulnLinks;
	}

	
	/**
	 * 
	 * @param s the source code of the targeted page
	 * @param inputTags list of input parameters
	 * @return the set of url form and input parameters
	 */
	public TreeSet<HtmlParameter> getParams(Source s, List<Element> inputTags) {
		
		// We store all the page fields in a hash map and add the payload
		TreeSet<HtmlParameter> tags = new TreeSet<HtmlParameter>();

		for (HtmlParameter p : getBaseMsg().getFormParams()) {
			if (p.getName() != null && p.getValue() != null) {
				tags.add(new HtmlParameter(HtmlParameter.Type.url, p.getName(), p.getValue() + this.payload));
				log.debug("The following form parameters have been found:");
				log.debug("Input Tag: " + p.getName() + ", " + p.getValue());
			}
		}
		for (HtmlParameter p : getBaseMsg().getUrlParams()) {
			if (p.getName() != null && p.getValue() != null) {
				tags.add(new HtmlParameter(HtmlParameter.Type.url, p.getName(), p.getValue() + this.payload));
				log.debug("The following url parameters have been found:");
				log.debug("Input Tag: " + p.getName() + ", " + p.getValue());
			}
		}
		for (Element element : inputTags) {
			if (element.getAttributeValue("name") != null && element.getAttributeValue("value") != null) {
				tags.add(new HtmlParameter(HtmlParameter.Type.url, element.getAttributeValue("name"), element.getAttributeValue("value")+ this.payload));
				log.debug("The following input parameters have been found:");
				log.debug("Input Tag: " + element.getAttributeValue("name") + ", " + element.getAttributeValue("value"));
			}
		}
		return tags;
	}
	
	
	/**
	 * 
	 * @param url found in the body of the targeted page
	 * @return a hashmap of the query string
	 */
	public Map<String, List<String>> getUrlParameters(String url) {
		Map<String, List<String>> params = new HashMap<String, List<String>>();

		String[] urlParts = url.split("\\?");
		if (urlParts.length > 1) {
			String query = urlParts[1];
			for (String param : query.split("&")) {
				String pair[] = param.split("=");
				String key;
				key = pair[0];
				String value = "";
				if (pair.length > 1) {
					value = pair[1];
				}
				List<String> values = params.get(key);
				if (values == null) {
					values = new ArrayList<String>();
					params.put(key, values);
				}
				values.add(value);
			}
		}
		return params;
	}
	
	
	/**
	 * 
	 * @param vulnLinks list of the vulnerable links in the page
	 */
	public void GenerateReport( List<String> vulnLinks) {
		String vulnParams = "";
		for(String s : vulnLinks) {
			vulnParams = vulnParams + ", " + s;
		}
		log.debug("Page vulnerable to HPP attacks");
		String attack = this.getString("HTTPParamPoll.alert.attack");
		try {
			bingo(Alert.RISK_MEDIUM, Alert.WARNING, attack, getDescription(),getBaseMsg().getRequestHeader().getURI().getURI(), vulnParams, attack, getReference(), getSolution(), getBaseMsg());
		} catch (URIException e) {
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
	
}