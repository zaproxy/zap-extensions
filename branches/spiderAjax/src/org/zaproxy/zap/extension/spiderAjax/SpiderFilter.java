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
package org.zaproxy.zap.extension.spiderAjax;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import org.apache.log4j.Logger;
import com.crawljax.core.CandidateElement;
import com.crawljax.core.CrawlSession;
import com.crawljax.core.plugin.PreStateCrawlingPlugin;

/**
 * SpiderFilter is called before the crawling, it checks the candidates
 * and discards those according to the excluded ones
 *
 */
public class SpiderFilter implements PreStateCrawlingPlugin {
	private static final Logger logger = Logger.getLogger(ExtensionAjax.class);
	ArrayList<String> urls;
	boolean replaceInput = false;
	private ExtensionAjax extension;
	private SpiderThread thread;

	/**
	 * The class constructor
	 * 
	 * @param e extension
	 * @param t threat
	 */
	public SpiderFilter(ExtensionAjax e, SpiderThread t) {
		this.extension = e;
		this.thread = t;
	}

	/**
	 *  This method filters the candidates, deleting the unwanted ones according to the spider filter.
	 *  
	 * @param session current session of crawljax
	 * @param candidates candidates to crawl in the next state
	 */
	@Override
	public void preStateCrawling(CrawlSession session,
			List<CandidateElement> candidates) {

		String currentUrl = session.getBrowser().getCurrentUrl();

		// for each candidate
		for (int j = 0; j < candidates.size(); j++) {
			CandidateElement c = candidates.get(j);
			boolean ignore = false;
			
			// we find all the attributes
			for (int i = 0; i < c.getElement().getAttributes().getLength(); i++) {
				
				String candidateUrl = c.getElement().getAttributes().item(i).getNodeValue();
				String guessedUrl = null;
				// here we try to guess the candidate URL...
				guessedUrl = candidateUrl;
				URL u;
				try {
					if (logger.isDebugEnabled()) {
						logger.debug("CurrentURL:" + currentUrl + " CandidateURL:" + candidateUrl);
					}
					// the candidate can be an URL or other stuff such as javascript:xx, here we determine what it is
					if (!candidateUrl.toLowerCase().contains("javascript")
							&& (candidateUrl.endsWith(".html")
									|| candidateUrl.endsWith(".asp")
									|| candidateUrl.endsWith(".php")
									|| candidateUrl.endsWith(".htm")
									|| candidateUrl.endsWith(".jsp")
									|| candidateUrl.endsWith(".aspx")
									|| candidateUrl.endsWith(".py")
									|| candidateUrl.endsWith(".xml")
									|| candidateUrl.contains("/"))) {
						u = new URL(new URL(currentUrl), candidateUrl);
					} else {
						u = new URL(currentUrl);
					}
					guessedUrl = u.toString();
				} catch (MalformedURLException e) {
					logger.error(e);
				}

				// we match the candidate URL with the ones that we do not want to crawl
				for (String excl : this.extension.getModel().getSession().getExcludeFromSpiderRegexs()) {
					Pattern p = Pattern.compile(excl, Pattern.CASE_INSENSITIVE);
					if (p.matcher(guessedUrl).matches()) {
						ignore = true;
						if (logger.isDebugEnabled()) {
							logger.debug("The following URL is filtered: " + excl);
							logger.debug("Candidate Element will be removed: " + guessedUrl);
						}
					}
				}

			}
			// if matched we remove the candidate
			if (ignore) {
				session.getCurrentState().getUnprocessedCandidateElements().remove(c.getElement());
				candidates.remove(c);
				session.getCrawlPaths().remove(c.getElement());
				session.getCurrentCrawlPath().remove(c.getElement());
			}
		}
	}
}
