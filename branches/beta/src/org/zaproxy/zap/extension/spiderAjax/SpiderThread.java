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

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import com.crawljax.core.CrawlSession;
import com.crawljax.core.CrawljaxController;
import com.crawljax.core.configuration.CrawlSpecification;
import com.crawljax.core.configuration.CrawljaxConfiguration;
import com.crawljax.core.configuration.ProxyConfiguration;
import com.crawljax.core.configuration.ThreadConfiguration;
import com.crawljax.core.plugin.PostCrawlingPlugin;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Session;
import org.zaproxy.zap.extension.spiderAjax.proxy.OverwriteMessageProxyListener;
import org.zaproxy.zap.network.HttpResponseBody;

public class SpiderThread implements Runnable {

	// crawljax config
	private static final boolean BROWSER_BOOTING = false;
	private static final int MAX_STATES = 0;
	private static final boolean RAND_INPUT_FORMS = true;
	private static final int MAX_DEPTH = 10;	// TODO - make this configurable by the user
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
	private final boolean spiderInScope;
	private boolean running;
	private final Session session;
	private static final Logger logger = Logger.getLogger(SpiderThread.class);

	private HttpResponseHeader outOfScopeResponseHeader;
	private HttpResponseBody outOfScopeResponseBody;
	private List<SpiderListener> spiderListeners;

	/**
	 * 
	 * @param url
	 * @param extension
	 * @param inScope
	 */
	SpiderThread(String url, ExtensionAjax extension, boolean inScope, SpiderListener spiderListener) {
		this.url = url;
		this.extension = extension;
		this.spiderInScope = inScope;
		this.running = false;
		spiderListeners = new ArrayList<>(2);
		spiderListeners.add(spiderListener);
		//by default we will use 1 browser & thread
		this.numBrowsers = this.extension.getProxy().getBrowsers();
		this.numThreads = this.extension.getProxy().getThreads();
		this.session = extension.getModel().getSession();
		this.initiProxy();

		createOutOfScopeResponse(extension.getMessages().getString("spiderajax.outofscope.response"));
	}

	private void createOutOfScopeResponse(String response) {
		outOfScopeResponseBody = new HttpResponseBody();
		outOfScopeResponseBody.setBody(response.getBytes(StandardCharsets.UTF_8));

		final StringBuilder strBuilder = new StringBuilder(150);
		final String crlf = HttpHeader.CRLF;
		strBuilder.append("HTTP/1.1 403 Forbidden").append(crlf);
		strBuilder.append(HttpHeader.PRAGMA).append(": ").append("no-cache").append(crlf);
		strBuilder.append(HttpHeader.CACHE_CONTROL).append(": ").append("no-cache").append(crlf);
		strBuilder.append(HttpHeader.CONTENT_TYPE).append(": ").append("text/plain; charset=UTF-8").append(crlf);
		strBuilder.append(HttpHeader.CONTENT_LENGTH).append(": ").append(outOfScopeResponseBody.length()).append(crlf);

		HttpResponseHeader responseHeader;
		try {
			responseHeader = new HttpResponseHeader(strBuilder.toString());
		} catch (HttpMalformedHeaderException e) {
			logger.error("Failed to create a valid! response header: ", e);
			responseHeader = new HttpResponseHeader();
		}
		outOfScopeResponseHeader = responseHeader;
	}

	
	/**
	 * This method refreshes the proxy
	 */
	private void initiProxy() {
		this.extension.getProxy().updateProxyConf();
		this.extension.getProxy().getProxy().removeOverwriteMessageProxyListeners();
		this.extension.getProxy().getProxy().addOverwriteMessageProxyListener(new SpiderProxyListener());
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
			crawlConf.addPlugin(new SpiderPostCrawlingPlugin());
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
			crawler.setClickOnce(true);
			// TODO - make this configurable by the user
			crawler.setWaitTimeAfterEvent(1000);
			if (this.extension.getProxy().getMegaScan()) {
				crawler.clickMoreElements();
			} else {
				crawler.clickDefaultElements();
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
		notifyListenersSpiderStarted();
		logger.info("Running crawljax targeting " + this.url );
		Logger.getLogger("org.parosproxy.paros.core.proxy.ProxyThread").setLevel(Level.OFF);
		Logger.getLogger("com.crawljax.browser.WebDriverBackedEmbeddedBrowser").setLevel(Level.OFF);
		Logger.getLogger("org.openqa.selenium.remote.ErrorHandler").setLevel(Level.OFF);
		Logger.getLogger("com.crawljax.core.state.StateVertix").setLevel(Level.OFF);
		Logger.getLogger("com.gargoylesoftware").setLevel(Level.OFF);
		Logger.getLogger("org.parosproxy.paros.network").setLevel(Level.OFF);
		Logger.getLogger("org.openqa.selenium.remote").setLevel(Level.OFF);
		Logger.getLogger("org.parosproxy.paros.view.SiteMapPanel").setLevel(Level.OFF);
		try {
			crawljax = new CrawljaxController(getCrawConf());
			crawljax.run();		
		} catch (Exception e) {
			logger.error(e, e);
		} finally {
			notifyListenersSpiderStoped();
		}
	}

	/**
	 * called by the buttons of the panel to stop the spider
	 */
	public void stopSpider() {
		logger.info("Finished crawljax targeting " + this.url );
		this.running = false;
		try {
		crawljax.terminate(false);
		} catch (Exception e) {
			logger.error(e, e);
		} finally {
			notifyListenersSpiderStoped();
		}
	}

	public void addSpiderListener(SpiderListener spiderListener) {
		spiderListeners.add(spiderListener);
	}

	public void removeSpiderListener(SpiderListener spiderListener) {
		spiderListeners.remove(spiderListener);
	}

	private void notifyListenersSpiderStarted() {
		for (SpiderListener listener : spiderListeners) {
			listener.spiderStarted();
		}
	}

	private void notifySpiderListenersFoundMessage(HistoryReference historyReference, HttpMessage httpMessage) {
		for (SpiderListener listener : spiderListeners) {
			listener.foundMessage(historyReference, httpMessage);
		}
	}

	private void notifyListenersSpiderStoped() {
		for (SpiderListener listener : spiderListeners) {
			listener.spiderStopped();
		}
	}

	private class SpiderPostCrawlingPlugin implements PostCrawlingPlugin {

		@Override
		public void postCrawling(CrawlSession arg0) {
			notifyListenersSpiderStoped();
		}
	}

	private class SpiderProxyListener implements OverwriteMessageProxyListener {

		@Override
		public int getArrangeableListenerOrder() {
			return 0;
		}

		@Override
		public boolean onHttpRequestSend(HttpMessage httpMessage) {
			final String uri = httpMessage.getRequestHeader().getURI().toString();
			if (spiderInScope && !session.isInScope(uri)) {
				logger.debug("Excluding request [" + uri + "] not in scope.");
				setOutOfScopeResponse(httpMessage);
				return true;
			}

			return false;
		}

		private void setOutOfScopeResponse(HttpMessage httpMessage) {
			try {
				httpMessage.setResponseHeader(outOfScopeResponseHeader.toString());
			} catch (HttpMalformedHeaderException ignore) {
				// Setting a valid response header.
			}
			httpMessage.setResponseBody(outOfScopeResponseBody.getBytes());
		}

		@Override
		public boolean onHttpResponseReceived(HttpMessage httpMessage) {
			try {
				HistoryReference historyRef = new HistoryReference(session, HistoryReference.TYPE_SPIDER_AJAX, httpMessage);
				historyRef.setCustomIcon("/resource/icon/10/spiderAjax.png", true);
				session.getSiteTree().addPath(historyRef, httpMessage);
				notifySpiderListenersFoundMessage(historyRef, httpMessage);
			} catch (Exception e) {
				logger.error(e);
			}

			return false;
		}
	}
}
