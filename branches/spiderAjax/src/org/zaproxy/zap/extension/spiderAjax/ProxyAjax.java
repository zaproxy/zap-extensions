package org.zaproxy.zap.extension.spiderAjax;

import org.parosproxy.paros.control.Proxy;
import org.parosproxy.paros.core.proxy.ProxyParam;
import org.parosproxy.paros.model.Model;

public class ProxyAjax {
	private ProxyParam proxyParam = null;
	private Proxy proxy = null;
	private Model modProxy = null;
	private boolean megaScan = false;

	// default config for the new ajax proxy
	private int proxyPort = 8081;
	private String proxyHost = "localhost";

	/**
	 * constructor for the new ajax proxy
	 */
	public ProxyAjax() {
		this.proxy = new Proxy(getProxyModel());
		this.proxy.startServer();
	}

	/**
	 * Initializes the Model for the proxy
	 */
	private Model getProxyModel() {
		modProxy = new Model();
		modProxy.getOptionsParam().setProxyParam(getSpiderParam());
		return modProxy;
	}

	/**
	 * sets the crawljax to megascan mode
	 */
	public void setMegaScan(boolean b) {
		this.megaScan = b;
	}

	/**
	 * reads if the crawljax is set to megascan mode
	 */
	public boolean getMegaScan() {
		return this.megaScan;
	}

	/**
	 * stops the sever, updates the config and starts it again
	 */
	public void updateProxyConf() {
		this.proxy.stopServer();
		this.proxy = new Proxy(getProxyModel());
		this.proxy.startServer();

	}

	/**
	 * stops the new ajax proxy
	 */
	public void stopServer() {
		this.getProxy().stopServer();

	}

	/**
	 * @return the new ajax proxy object
	 */
	public Proxy getProxy() {
		return this.proxy;
	}

	/**
	 * @return the current port used by the new ajax proxy
	 */
	public int getProxyPort() {
		return this.proxyPort;
	}

	/**
	 * @return the current host used by the new ajax proxy
	 */
	public String getProxyHost() {
		return this.proxyHost;
	}

	/**
	 * 
	 * @param host
	 */
	public void setProxyHost(String host) {
		this.proxyHost = host;
	}

	/**
	 * 
	 * @param port
	 */
	public void setProxyPort(int port) {
		this.proxyPort = port;
	}

	/**
	 * sets the new config for the proxy
	 * 
	 * @return the parameter for the proxy with the new config
	 */
	public ProxyParam getSpiderParam() {
		proxyParam = new ProxyParam(this.getProxyPort());
		// TODO fix the new IP bug
		// proxyParam.setProxyIp(this.getProxyHost());
		return proxyParam;
	}

}
