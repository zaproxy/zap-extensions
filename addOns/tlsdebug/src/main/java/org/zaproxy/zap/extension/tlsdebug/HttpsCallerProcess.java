/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP development team
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS"
 * BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language
 * governing permissions and limitations under the License.
 */
package org.zaproxy.zap.extension.tlsdebug;

import java.net.MalformedURLException;
import java.net.URL;

import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.protocol.Protocol;
import org.apache.commons.httpclient.protocol.ProtocolSocketFactory;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.parosproxy.paros.network.SSLConnector;

public class HttpsCallerProcess {

	private static final String HTTPS = "https";

	public static void main(String[] args) {
		if (args.length < 1) {
			System.out.println("URL not set! Please give an URL as argument.");
			System.exit(-1);
		}

		try {
			String urlStrg = args[0];
			URL url = new URL(urlStrg);
			if (!HTTPS.equals(url.getProtocol())) {
				throw new IllegalArgumentException("Please choose https protocol! " + url);
			}

			Protocol.registerProtocol(HTTPS, new Protocol(HTTPS, (ProtocolSocketFactory) new SSLConnector(), 443));

			HttpMessage msg = accessURL(url);
			if (msg != null) {
				System.out.println(msg.getResponseHeader());
			}
			System.out.println("--- END of call -------------------------------------------------");
		} catch (MalformedURLException e) {
			e.printStackTrace();
		}
		System.out.close();
		System.err.close();
	}

	private static HttpMessage accessURL(URL url) {
		// Request the URL
		try {
			final HttpMessage msg = new HttpMessage(new URI(url.toString(), true));
			getHttpSender().sendAndReceive(msg, true);
			return msg;
		} catch (Exception e1) {
			e1.printStackTrace();
		}
		return null;

	}

	private static HttpSender getHttpSender() {
		HttpSender httpSender = new HttpSender(Model.getSingleton().getOptionsParam().getConnectionParam(), true,
				HttpSender.MANUAL_REQUEST_INITIATOR);

		return httpSender;
	}
}
