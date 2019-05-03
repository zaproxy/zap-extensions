/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2015 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.zest;

import org.apache.log4j.Logger;
import org.mozilla.zest.core.v1.ZestAuthentication;
import org.mozilla.zest.core.v1.ZestRequest;
import org.mozilla.zest.core.v1.ZestResponse;
import org.mozilla.zest.impl.ZestHttpClient;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.network.DefaultHttpRedirectionValidator;
import org.zaproxy.zap.network.HttpRequestConfig;

import java.io.IOException;
import java.net.MalformedURLException;
import java.sql.SQLException;

public class ZestHttpSender implements ZestHttpClient {

	private static final Logger logger = Logger.getLogger(ZestHttpSender.class);
	private HttpSender httpSender;
	private ZestParam param;

	public ZestHttpSender(ZestParam param) {
		this.param = param;
		this.httpSender = new HttpSender(Model.getSingleton().getOptionsParam().getConnectionParam(),true, HttpSender.MANUAL_REQUEST_INITIATOR);
	}

	public ZestHttpSender(HttpSender httpSender, ZestParam param) {
		this.httpSender = httpSender;
		this.param = param;
	}

	@Override
	public void setAuthentication(ZestAuthentication zestAuthentication) {

	}

	@Override
	public void setProxy(String s, int i) {

	}

	@Override
	public ZestResponse send(ZestRequest zestRequest) throws IOException {
		HttpMessage msg = ZestZapUtils.toHttpMessage(zestRequest, null);

		if(zestRequest.isFollowRedirects()){
			HttpRequestConfig config = HttpRequestConfig
					.builder()
					.setRedirectionValidator(DefaultHttpRedirectionValidator.INSTANCE)
					.setFollowRedirects(true)
					.build();

			httpSender.sendAndReceive(msg, config);
		}else{
			httpSender.sendAndReceive(msg,false);
		}

		updateZestRequestFromMessage(zestRequest, msg);
		return ZestZapUtils.toZestResponse(msg);
	}

	// Update ZestRequest from HttpMessage. Otherwise added SessionCookies would be lost.
	// That could be interesting for ZestAssignments or ZestAsserts.
	private void updateZestRequestFromMessage(ZestRequest zestRequest, HttpMessage msg) throws MalformedURLException, HttpMalformedHeaderException {
		try {
			ZestZapUtils.updateZestRequest(zestRequest, msg, false, true, param);
		} catch (SQLException e) {
			logger.warn("Error converting HttpMessage to  ZestRequest: " + e.getMessage());
		}
	}
}
