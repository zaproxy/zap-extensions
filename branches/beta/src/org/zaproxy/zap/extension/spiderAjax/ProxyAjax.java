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

import org.apache.log4j.Logger;
import org.openqa.selenium.chrome.ChromeDriver;
import org.parosproxy.paros.network.ConnectionParam;
import org.zaproxy.zap.extension.spiderAjax.proxy.ProxyServer;

/**
 * This class manages the ajax spider proxy server
 *
 */
public class ProxyAjax {
	
	private ProxyServer proxy = null;
	private ExtensionAjax extension;
	private static final Logger logger = Logger.getLogger(ProxyAjax.class);

	private final AjaxSpiderParam ajaxSpiderParam;
	
	/**
	 * constructor
	 * @param e the extension
	 */
	public ProxyAjax(ExtensionAjax e, AjaxSpiderParam ajaxSpiderParam, ConnectionParam connectionParam) {
		extension = e;
		this.ajaxSpiderParam = ajaxSpiderParam;
		this.getProxy();
		this.proxy.setConnectionParam(connectionParam);
		this.proxy.startServer(ajaxSpiderParam.getProxyIp(), ajaxSpiderParam.getProxyPort(), false);
	}

	/**
	 * stops the sever, updates the config and starts it again
	 */
	public void updateProxyConf() {
		// XXX Consider to remove the following two statements as the method
		// ProxyServer.startServer already stops the server (if it was running).
		if(this.proxy.isAnyProxyThreadRunning()){
			this.proxy.stopServer();
		}
		this.proxy.startServer(ajaxSpiderParam.getProxyIp(), ajaxSpiderParam.getProxyPort(), false);
		if(this.extension.getExcludeList()!=null){
			this.proxy.setExcludeList(this.extension.getExcludeList());
		}
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
	public ProxyServer getProxy() {
		if (this.proxy == null) {
			this.proxy = new ProxyServer();
		}
		return proxy;
	}

	/**
	 * This method checks if the chromedriver is available
	 * @return true if available, false otherwise.
	 */
	public boolean isChromeAvail(){
		try{
			new ChromeDriver().close();
		} catch (Exception e) {
			logger.error(e);
			return false;
		}
		return true;
	}
}
