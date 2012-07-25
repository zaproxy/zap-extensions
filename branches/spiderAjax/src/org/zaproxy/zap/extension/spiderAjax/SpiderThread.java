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


import java.util.regex.Pattern;
import com.crawljax.core.CrawljaxController;
import com.crawljax.core.CrawljaxException;
import com.crawljax.core.configuration.CrawlSpecification;
import com.crawljax.core.configuration.CrawljaxConfiguration;
import com.crawljax.core.configuration.ProxyConfiguration;
import com.crawljax.core.configuration.ThreadConfiguration;

import org.apache.commons.configuration.ConfigurationException;
import org.apache.log4j.Logger;
import org.parosproxy.paros.core.proxy.ProxyListener;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.SiteMap;

public class SpiderThread implements Runnable, ProxyListener {

	// crawljax config
	private static final int NUM_BROWSERS = 1;
	private static final int NUM_THREADS = 2;
	private static final boolean BROWSER_BOOTING = true;
	private static final int MAX_STATES = 100;
	private static final boolean RAND_INPUT_FORMS = true;
	private static final int MAX_DEPTH = 100;

	private String url = null;
	private ExtensionAjax extension = null;
	private String host = null;
	private int port;
	private CrawljaxConfiguration crawlConf = null;
	private ThreadConfiguration threConf = null;
	private CrawljaxController crawljax = null;
	private CrawlSpecification crawler = null;
	private ProxyConfiguration proxyConf = null;
	private static final Logger logger = Logger.getLogger(SpiderThread.class);

	SpiderThread(String url, ExtensionAjax extension) {
		this.url = url;
		this.extension = extension;
		initialize();
	}

	
	/**
	 * This method refreshes the proxy
	 * @return void
	 */
	private void initialize() {
		this.extension.getProxy().updateProxyConf();
		this.extension.getProxy().getProxy().addProxyListener(this);
	    this.extension.getSpiderPanel().getListLog().setModel(this.extension.getSpiderPanel().getHistList());
		if (this.extension.getExcludeList() != null) {
			this.extension.getProxy().getProxy();//.setExcludeList(this.extension.getExcludeList());
		}
	}

	
	/** 
	 * @return the port to be used by crawljax
	 */
	public int getPort() {
		return this.port;
	}

	
	/**
	 * @return the host to be used in the proxy config
	 */
	public String getHost() {
		return this.host;
	}

	
	/**
	 * @return the proxy configuration of crawljax
	 */
	public ProxyConfiguration getProxyConf() {
		if (proxyConf == null) {
			proxyConf = new ProxyConfiguration();
			proxyConf.setHostname(this.getHost());
			proxyConf.setPort(this.getPort());
		}
		return proxyConf;
	}

	
	/**
	 * @return the thread configuration for crawljax
	 */
	public ThreadConfiguration getThreadConf() {
		if (threConf == null) {
			threConf = new ThreadConfiguration();
			threConf.setBrowserBooting(BROWSER_BOOTING);
			threConf.setNumberBrowsers(NUM_BROWSERS);
			threConf.setNumberThreads(NUM_THREADS);
		}
		return threConf;
	}

	/**
	 * @return the crawljax configuration (thread conf+spec+proxy conf+plugins)
	 */
	public CrawljaxConfiguration getCrawConf() {
		if (crawlConf == null) {
			crawlConf = new CrawljaxConfiguration();
			crawlConf.setThreadConfiguration(this.getThreadConf());
			crawlConf.setBrowser(this.extension.getProxy().getBrowser());
			crawlConf.setCrawlSpecification(this.getCrawSpec());
			this.port = this.extension.getProxy().getProxyPort();
			this.host = this.extension.getProxy().getProxyHost();
			crawlConf.setProxyConfiguration(this.getProxyConf());

			// we add the plugins
			crawlConf.addPlugin(new SpiderFilter(this.extension, this));
		}
		return crawlConf;
	}

	/**
	 * @return the new crawljax specification
	 */
	public CrawlSpecification getCrawSpec() {
		if (crawler == null) {
			crawler = new CrawlSpecification(this.url);
			crawler.setMaximumStates(MAX_STATES);
			crawler.setDepth(MAX_DEPTH);
			crawler.setRandomInputInForms(RAND_INPUT_FORMS);
			if (this.extension.getProxy().getMegaScan()) {
				crawler.clickAllElements();
			} else {
				crawler.clickDefaultElements();
			}
			//TODO: fix this in crawljax
			if (url.toLowerCase().contains("wivet")) {
				crawler.dontClick("a").withAttribute("href","../innerpages/2_2.php");
			}
		}
		return crawler;
	}

	@Override
	public void run() {

		// testing crawljax plugins
		// crawljaxConfiguration.addPlugin(new test(true));

		try {
			crawljax = new CrawljaxController(getCrawConf());
			
        } catch (ConfigurationException e) {
			logger.error(e);
        } catch (Exception e) {
			logger.error(e);
		}
		try {
			crawljax.run();
			
		} catch (CrawljaxException e) {
			logger.error(e);
		} catch (Exception e) {
			logger.error(e);
		}
	}
	
	@Override
	public boolean onHttpRequestSend(HttpMessage msg) {
		return true;
	}

	
	@Override
	public boolean onHttpResponseReceive(HttpMessage msg) {
		SiteMap siteTree = extension.getModel().getSession().getSiteTree();
		HistoryReference historyRef = null;

		try {

			//int ref=msg.getHistoryRef().getSiteNode().addIcon("/org/zaproxy/zap/extension/spiderAjax/10.png");
			
			//we check if it has to be put in the sites tree or is already there
			historyRef = new HistoryReference(extension.getModel().getSession(),"/resource/icon/10/spiderAjax.png", msg, true);
			boolean ignore =false;
			for (String pa : this.extension.getModel().getSession().getExcludeFromScanRegexs()) {
				Pattern p = Pattern.compile(pa, Pattern.CASE_INSENSITIVE);
				if (p.matcher(msg.getRequestHeader().getURI().toString()).matches()) {
					ignore=true;
				}
			}
			if(!ignore){
				siteTree.addPath(historyRef, msg);
			}
		} catch (Exception e) {
			logger.error(e);
		}
		try {
		this.extension.getSpiderPanel().addHistoryUrl(historyRef, msg);
		} catch (Exception e){
			logger.error(e);
		}
		return true;
	}

	@Override
	public int getProxyListenerOrder() {
		return 0;
	}
}
