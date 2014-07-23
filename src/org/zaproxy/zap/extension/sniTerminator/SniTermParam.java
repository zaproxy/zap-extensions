/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2011 mawoki@ymail.com
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
package org.zaproxy.zap.extension.sniTerminator;

import org.apache.log4j.Logger;
import org.parosproxy.paros.common.AbstractParam;

/**
 * @author psiinon
 */
public class SniTermParam extends AbstractParam {

	private static final String PARAM_SERVER_ADDRESS = "sniterm.server.address";
	private static final String PARAM_SERVER_PORT = "sniterm.server.port";

	private static final String DEFAULT_SERVER_ADDRESS = "0.0.0.0";
	private static final int DEFAULT_SERVER_PORT = 8443;

	private String serverAddress = null;
	private int serverPort = -1;

	private final Logger logger = Logger.getLogger(SniTermParam.class);

	@Override
	protected void parse() {
		try {
			serverAddress = getConfig().getString(PARAM_SERVER_ADDRESS, DEFAULT_SERVER_ADDRESS);
			serverPort = getConfig().getInt(PARAM_SERVER_PORT, DEFAULT_SERVER_PORT);
		} catch (final Exception e) {
			logger.warn("Couldn't load SNI terminator parameters", e);
		}
	}
	
	public String getServerAddress() {
		return serverAddress;
	}

	public int getServerPort() {
		return serverPort;
	}

	public void setServerAddress(String serverAddress) {
		this.serverAddress = serverAddress;
		getConfig().setProperty(PARAM_SERVER_ADDRESS, serverAddress);
	}

	public void setServerPort(int serverPort) {
		this.serverPort = serverPort;
		getConfig().setProperty(PARAM_SERVER_PORT, serverPort);
	}
}

