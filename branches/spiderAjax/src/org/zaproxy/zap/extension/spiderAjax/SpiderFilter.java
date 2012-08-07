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
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import org.apache.log4j.Logger;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import com.crawljax.core.CandidateElement;
import com.crawljax.core.CrawlSession;
import com.crawljax.core.plugin.PreStateCrawlingPlugin;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;

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
	private CrawlSession sess;
	private List<CandidateElement> cands;

	/**
	 * The class constructor
	 * 
	 * @param e extension
	 * @param t thread
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
		this.sess = session;
		this.cands = candidates;
		filterExcluded(this.sess, this.cands);
		//if the scope is limited we filter the candidates
		/*if (this.thread.isInScope()) {
			filterScope(this.sess, this.cands);
		}*/
		session = this.sess;
		candidates = this.cands;
	}
	
	/**
	 * 
	 * @param session
	 * @param candidates
	 */
	private void filterScope(CrawlSession session, List<CandidateElement> candidates) {
		try {
			for(CandidateElement cand: candidates) {
			for (int i = 0; i < cand.getElement().getAttributes().getLength(); i++) {
				String guessedUrl = getCandidateUrl(cand.getElement().getAttributes().item(i).getNodeValue(), session.getBrowser().getCurrentUrl());
				URI url = new URI(guessedUrl, false);
				HttpMessage msg = new HttpMessage(url);
				HistoryReference historyRef = new HistoryReference(extension.getModel().getSession(), HistoryReference.TYPE_SPIDER_AJAX, msg);
				SiteNode n = new SiteNode(this.extension.getModel().getSession().getSiteTree(), HistoryReference.TYPE_SPIDER_AJAX, "name");
				n.setHistoryReference(historyRef);
				/* n.setIncludedInScope(this.extension.getModel().getSession().isInScope(n), true);
	            //n.setExcludedFromScope(this.extension.getModel().getSession().getSiteTree(), true);
	            if(!n.isIncludedInScope()) {
	            	candidates.remove(cand);
	            	if (logger.isDebugEnabled()) {
						logger.debug("The following URL is out of scope and will be removed: " + guessedUrl);
					} else {
						System.out.println("The following URL is out of scope and will be removed: " + guessedUrl);
					}
	            }*/
			}
		}
		} catch (URIException e) {
			logger.error(e);
		} catch (HttpMalformedHeaderException e) {
			logger.error(e);
		} catch (SQLException e) {
			logger.error(e);
		}
		this.cands = candidates;
	}
	
	
	/**
	 * 
	 * @param session
	 * @param candidates
	 */
	private void filterExcluded(CrawlSession session, List<CandidateElement> candidates) {
		String currentUrl = session.getBrowser().getCurrentUrl();

		// for each candidate
		for (int j = 0; j < candidates.size(); j++) {
			CandidateElement c = candidates.get(j);
			boolean ignore = false;
			
			// we find all the attributes
			for (int i = 0; i < c.getElement().getAttributes().getLength(); i++) {
				
				String guessedUrl = getCandidateUrl(c.getElement().getAttributes().item(i).getNodeValue(), currentUrl);

				// we match the candidate URL with the ones that we do not want to crawl
				for (String excl : this.extension.getModel().getSession().getExcludeFromSpiderRegexs()) {
					Pattern p = Pattern.compile(excl, Pattern.CASE_INSENSITIVE);
					if (p.matcher(guessedUrl).matches()) {
						ignore = true;
						if (logger.isDebugEnabled()) {
							logger.debug("The following URL is filtered: " + excl);
							logger.debug("Candidate Element will be removed: " + guessedUrl);
						}else {
							System.out.println("Candidate Element will be removed: " + guessedUrl);
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
		this.cands = candidates;
		this.sess = session;
	}
	
	
	private String getCandidateUrl(String candidateUrl, String currentUrl) {
		String guessedUrl = null;
		// here we try to guess the candidate URL...
		guessedUrl = candidateUrl;
		URL u = null;
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
		} catch (Exception e) {
			logger.error(e);
		}
		return guessedUrl;
	}
}
