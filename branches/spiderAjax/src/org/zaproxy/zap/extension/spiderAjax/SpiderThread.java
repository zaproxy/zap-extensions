package org.zaproxy.zap.extension.spiderAjax;

import java.util.ArrayList;
import java.util.List;
import javax.swing.ListModel;
import com.crawljax.browser.EmbeddedBrowser.BrowserType;
import com.crawljax.core.CrawljaxController;
import com.crawljax.core.CrawljaxException;
import com.crawljax.core.configuration.CrawlSpecification;
import com.crawljax.core.configuration.CrawljaxConfiguration;
import com.crawljax.core.configuration.ProxyConfiguration;
import com.crawljax.core.configuration.ThreadConfiguration;
import org.parosproxy.paros.core.proxy.ProxyListener;
import org.parosproxy.paros.extension.history.ProxyListenerLog;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.SiteMap;
import org.zaproxy.zap.model.ScanListenner;
import org.zaproxy.zap.model.ScanThread;

public class SpiderThread implements Runnable, ProxyListener, ScanListenner {

	public static final int PROXY_LISTENER_ORDER = ProxyListenerLog.PROXY_LISTENER_ORDER + 1;

	// crawljax config
	private static final int NUM_BROWSERS = 1;
	private static final int NUM_THREADS = 1;
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

	SpiderThread(String url, ExtensionAjax extension) {
		this.url = url;
		this.extension = extension;
		initialize();
	}

	/**
	 * This method refreshes de proxy
	 * 
	 * @return void
	 */
	private void initialize() {
		this.extension.getProxy().updateProxyConf();
		this.extension.getProxy().getProxy().addProxyListener(this);
	}

	/**
	 * 
	 * @return the port to be used by crawljax
	 */
	public int getPort() {
		return this.port;
	}

	/**
	 * 
	 * @return the host to be used in the proxy config
	 */
	public String getHost() {
		return this.host;
	}

	/**
	 * 
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
	 * 
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
	 * 
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
			
			//we add the plugins
			crawlConf.addPlugin(new test2(this.extension, this));
		}
		return crawlConf;
	}

	/**
	 * 
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
			if (url.contains("wivet")) {
				crawler.dontClick("a").withAttribute("href",
						"../innerpages/2_2.php");
				crawler.dontClick("a").withText("Logout");
			}
			for(String excl:this.extension.getModel().getSession().getExcludeFromSpiderRegexs()){

			}
			//crawler.dontClick("*").withAttribute("href", "http://aopcgr.uab.es:10001/wivet/");
			//crawler.dontClick("").withAttribute("href", "http://aopcgr.uab.es:10001/wivet/");
			//crawler.dontClick("a").withAttribute("href", "http://aopcgr.uab.es:10001/wivet/");
			
		}
		return crawler;
	}

	@Override
	public void run() {

		// to use ACT instead of crawljax

		/*
		 * CrawlRequest request = new CrawlRequest(url);
		 * request.setBrowserType(BrowserType.firefox);
		 * request.addClickElement() request.setMaxDepth(0);
		 * request.setMaxDuration(0); request.setMaxStates(0);
		 * request.setClickDefaults(true); request.setCrawlFrames(true);
		 * request.setRandomInput(true); request.setCrawlOnce(true);
		 * request.isTestInvariants(); request.setUseProxy(true);
		 * request.setProxyUrl("localhost"); request.setProxyPort(8080);
		 * CrawlerRunnable run = new CrawlerRunnable(request); run.run();
		 */

		// testing crawljax plugins
		// crawljaxConfiguration.addPlugin(new test(true));

		try {
			crawljax = new CrawljaxController(getCrawConf());
		} catch (Exception e) {
			e.printStackTrace();
		}
		try {
			crawljax.run();
		} catch (CrawljaxException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	@Override
	public boolean onHttpRequestSend(HttpMessage msg) {
		String site = msg.getRequestHeader().getHostName();
		if (msg.getRequestHeader().getHostPort() > 0
				&& msg.getRequestHeader().getHostPort() != 80) {
			site += ":" + msg.getRequestHeader().getHostPort();
		}
		this.extension.getSpiderPanel().addSite(site, true);
		return true;
	}

	@Override
	public boolean onHttpResponseReceive(HttpMessage msg) {
		SiteMap siteTree = extension.getModel().getSession().getSiteTree();
		// this.extension.getProxy();
		HistoryReference historyRef = null;
		try {
			historyRef = new HistoryReference(
					extension.getModel().getSession(),
					HistoryReference.TYPE_SPIDERAJAX, msg);
			siteTree.addPath(historyRef, msg);
		} catch (Exception e) {
		}
		// this.extension.getModel().addSessionListener(this));
		if (extension.getView() != null) {
			if (!msg.getRequestHeader().getURI().toString().contains(this.url)) {
				extension.getSpiderPanel().appendFoundButSkip(
						msg.getRequestHeader().getURI().toString() + "\n");
			} else {
				extension.getSpiderPanel().appendFound(
						msg.getRequestHeader().getURI().toString() + "\n");
			}
		}
		return true;
	}

	@Override
	public void scanFinshed(String arg0) {
	}

	@Override
	public void scanProgress(String site, int progress, int maximum) {
	}

	@Override
	public int getProxyListenerOrder() {
		return PROXY_LISTENER_ORDER;
	}
}
