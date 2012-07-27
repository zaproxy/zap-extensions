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
import org.parosproxy.paros.core.proxy.ProxyParam;

public class AjaxProxyParam extends ProxyParam {
	private int proxyPort;
	private String proxyIp = null;
	private static final String PROXY_IP = "proxy.ip";
	private static final String PROXY_PORT = "proxy.port";
	private static final Logger logger = Logger.getLogger(AjaxProxyParam.class);


	/**
	 * constructor, if no IP and port specified, we set localhost:8081
	 */
	public AjaxProxyParam() {
		this.proxyIp="localhost";
		this.proxyPort=8081;
	}

	/**
	 * constructor, if no addr is specified, we use localhost
	 * @param port
	 */
	public AjaxProxyParam(int port) {
		this.proxyPort = port;
		this.proxyIp = "localhost";
	}
	/**
	 * constructor
	 * @param port
	 * @param ip
	 */
	public AjaxProxyParam(int port, String ip) {
		this.proxyPort = port;
		this.proxyIp=ip;
	}

	@Override
	protected void parse() {
		proxyIp = getConfig().getString(PROXY_IP, this.proxyIp);
		try {
			proxyPort = getConfig().getInt(PROXY_PORT, this.proxyPort);
		} catch (Exception e) {
			logger.error(e);
		}

	}
	
	/**
	 * @return the port of the parameter
	 */
	public int getProxyPort(){
		return this.proxyPort;
	}
	
	/**
	 * @return the IP of the parameter
	 */
	public String getProxyIp(){
		return this.proxyIp;
	}


	/**
	 * @param p
	 */
	public void setProxyPort(int p){
		this.proxyPort = p;
	}

	/**
	 * @param ip
	 */
	public void setProxyIp(String ip){
		this.proxyIp = ip;
	}

}
