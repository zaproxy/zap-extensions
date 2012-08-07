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


import java.util.ArrayList;
import java.util.regex.Pattern;
import com.crawljax.core.CrawljaxController;
import com.crawljax.core.CrawljaxException;
import com.crawljax.core.configuration.CrawlSpecification;
import com.crawljax.core.configuration.CrawljaxConfiguration;
import com.crawljax.core.configuration.ProxyConfiguration;
import com.crawljax.core.configuration.ThreadConfiguration;

import org.apache.commons.configuration.ConfigurationException;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.parosproxy.paros.core.proxy.ProxyListener;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.SiteMap;

public class SpiderThread implements Runnable, ProxyListener {

	// crawljax config
	private static final boolean BROWSER_BOOTING = false;
	private static final int MAX_STATES = 20;
	private static final boolean RAND_INPUT_FORMS = true;
	private static final int MAX_DEPTH = 20;
	private int numBrowsers;
	private int numThreads;
	private String url = null;
	private ExtensionAjax extension = null;
	private String host = null;
	private int port;
	private CrawljaxConfiguration crawlConf = null;
	private ThreadConfiguration threConf = null;
	private CrawljaxController crawljax = null;
	private CrawlSpecification crawler = null;
	private ProxyConfiguration proxyConf = null;
	private boolean spiderInScope;
	private boolean running;
	private static final Logger logger = Logger.getLogger(SpiderThread.class);

	SpiderThread(String url, ExtensionAjax extension, boolean inScope) {
		this.url = url;
		this.extension = extension;
		this.spiderInScope = inScope;
		this.running = false;
		this.initiProxy();
		//by default we will use 1 browser & thread
		this.numBrowsers = this.extension.getProxy().getBrowsers();
		this.numThreads = this.extension.getProxy().getThreads();
	}

	
	/**
	 * This method refreshes the proxy
	 * @return void
	 */
	private void initiProxy() {
		this.extension.getProxy().updateProxyConf();
		this.extension.getProxy().getProxy().addProxyListener(this);
	    this.extension.getSpiderPanel().getListLog().setModel(this.extension.getSpiderPanel().getHistList());
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
	 * 
	 * @return whether there is a scope defined
	 */
	public boolean isInScope() {
		return this.spiderInScope;
	}
	
	/**
	 * 
	 * @return the SpiderThread object
	 */
	public SpiderThread getSpiderThread() {
		return this;
	}
	/** 
	 * @return the # of threads to be used by crawljax
	 */
	public int getNumThreads() {
		return this.numThreads;
	}
	
	/** 
	 * @return the # of browsers to be used by crawljax
	 */
	public int getNumBrowsers() {
		return this.numBrowsers;
	}
	
	/**
	 * 
	 * @return the SpiderThread object
	 */
	public boolean isRunning() {
		return this.running;
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
			threConf.setNumberBrowsers(this.numBrowsers);
			threConf.setNumberThreads(this.numThreads);
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
				crawler.clickMoreElements();
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

	/**
	 * Instantiates the crawljax classes. 
	 */
	@Override
	public void run() {
		this.running = true;
		logger.info("Running crawljax targeting " + this.url );
		Logger.getLogger("org.parosproxy.paros.core.proxy.ProxyThread").setLevel(Level.OFF);
		Logger.getLogger("com.crawljax.browser.WebDriverBackedEmbeddedBrowser").setLevel(Level.OFF);
		Logger.getLogger("org.openqa.selenium.remote.ErrorHandler").setLevel(Level.OFF);
		Logger.getLogger("com.crawljax.core.state.StateVertix").setLevel(Level.OFF);
		Logger.getLogger("com.gargoylesoftware").setLevel(Level.OFF);
		Logger.getLogger("org.parosproxy.paros.network").setLevel(Level.OFF);
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
			//logger.error(e);
		} catch (Exception e) {
			//logger.error(e);
		} finally {
			this.running = false;
			crawljax.terminate(true);
			this.extension.getProxy().getProxy().stopServer();
			logger.info("Finished crawling " + this.url );

		}
	}
	
	@Override
	public boolean onHttpRequestSend(HttpMessage msg) {
		return true;
	}

	
	@Override
	public boolean onHttpResponseReceive(HttpMessage msg) {
		// we check if the scan is scope limited and if so if the node is in scope
		//if ((this.spiderInScope && msg.getHistoryRef().getSiteNode().isIncludedInScope()) || !this.spiderInScope) {
			//we check if it has to be put in the sites tree or is already there
			boolean ignore = false;
			for (String pa : this.extension.getModel().getSession().getExcludeFromScanRegexs()) {
				Pattern p = Pattern.compile(pa, Pattern.CASE_INSENSITIVE);
				if (p.matcher(msg.getRequestHeader().getURI().toString()).matches()) {
					ignore=true;
				}
			}
			if(!ignore){
				try {
					HistoryReference historyRef = new HistoryReference(extension.getModel().getSession(), HistoryReference.TYPE_SPIDER_AJAX, msg);
					historyRef.setCustomIcon("/resource/icon/10/spiderAjax.png", true);
					extension.getModel().getSession().getSiteTree().addPath(historyRef, msg);
					this.extension.getSpiderPanel().addHistoryUrl(historyRef, msg, this.url);
				} catch (Exception e){
					logger.error(e);
				}
			/*}*/
		}
		return true;
	}

	@Override
	public int getProxyListenerOrder() {
		return 0;
	}
	/**
	 * called by the buttons of the panel to stop the spider
	 */
	public void stopSpider() {
		if(this.isRunning()) {
			this.running = false;
			try {
			crawljax.terminate(false);
			this.extension.getProxy().getProxy().stopServer();
				Thread.currentThread().interrupt();
			} catch (Exception e) {
				logger.error(e);
			}
		}
	}
}
