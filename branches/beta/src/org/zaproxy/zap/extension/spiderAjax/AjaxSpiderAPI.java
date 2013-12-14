/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 * 
 * Copyright 2013 The ZAP Development Team
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	 http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.spiderAjax;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.GZIPInputStream;

import net.sf.json.JSONObject;

import org.apache.log4j.Logger;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.api.ApiAction;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.extension.api.ApiException.Type;
import org.zaproxy.zap.extension.api.ApiImplementor;
import org.zaproxy.zap.extension.api.ApiResponse;
import org.zaproxy.zap.extension.api.ApiResponseElement;
import org.zaproxy.zap.extension.api.ApiResponseList;
import org.zaproxy.zap.extension.api.ApiResponseSet;
import org.zaproxy.zap.extension.api.ApiView;

class AjaxSpiderAPI extends ApiImplementor implements SpiderListener {

	private static final Logger logger = Logger.getLogger(AjaxSpiderAPI.class);

	private static final String PREFIX = "ajaxSpider";

	private static final String ACTION_START_SCAN = "scan";
	private static final String ACTION_STOP_SCAN = "stop";

	private static final String VIEW_STATUS = "status";
	private static final String VIEW_RESULTS = "results";
	private static final String VIEW_NUMBER_OF_RESULTS = "numberOfResults";

	private static final String PARAM_URL = "url";
	private static final String PARAM_IN_SCOPE = "inScope";
	private static final String PARAM_START = "start";
	private static final String PARAM_COUNT = "count";

	private enum SpiderStatus {
		STOPPED,
		RUNNING;

		@Override
		public String toString() {
			return super.toString().toLowerCase();
		}
	}

	private final ExtensionAjax extension;

	private List<HistoryReference> historyReferences;
	private SpiderThread spiderThread;

	public AjaxSpiderAPI(ExtensionAjax extension) {
		this.extension = extension;
		this.historyReferences = Collections.emptyList();

		this.addApiAction(new ApiAction(ACTION_START_SCAN, new String[] { PARAM_URL }, new String[] { PARAM_IN_SCOPE }));
		this.addApiAction(new ApiAction(ACTION_STOP_SCAN));

		this.addApiView(new ApiView(VIEW_STATUS));
		this.addApiView(new ApiView(VIEW_RESULTS, null, new String[] { PARAM_START, PARAM_COUNT }));
		this.addApiView(new ApiView(VIEW_NUMBER_OF_RESULTS));

	}

	@Override
	public String getPrefix() {
		return PREFIX;
	}

	@Override
	public ApiResponse handleApiAction(String name, JSONObject params) throws ApiException {
		switch (name) {
		case ACTION_START_SCAN:
			String url = getParam(params, PARAM_URL, "");
			validateUrl(url);
			if (extension.isSpiderRunning()) {
				throw new ApiException(ApiException.Type.SCAN_IN_PROGRESS);
			}

			spiderThread = extension.createSpiderThread(url, getParam(params, PARAM_IN_SCOPE, false), this);
			try {
				new Thread(spiderThread).start();
			} catch (Exception e) {
				logger.error(e);
			}
			break;

		case ACTION_STOP_SCAN:
			stopSpider();
			break;
		default:
			throw new ApiException(ApiException.Type.BAD_ACTION);
		}
		return ApiResponseElement.OK;
	}

	private static void validateUrl(String url) throws ApiException {
		if ("".equals(url)) {
			throw new ApiException(Type.MISSING_PARAMETER, PARAM_URL);
		}
		try {
			@SuppressWarnings("unused")
			URL uri = new URL(url);
		} catch (MalformedURLException e) {
			if (logger.isDebugEnabled()) {
				logger.debug("Invalid url [" + url + "].", e);
			}
			throw new ApiException(Type.ILLEGAL_PARAMETER, PARAM_URL);
		}
	}

	@Override
	public ApiResponse handleApiView(String name, JSONObject params) throws ApiException {
		ApiResponse result;
		switch (name) {
		case VIEW_STATUS:
			result = new ApiResponseElement(name, isSpiderRunning()
					? SpiderStatus.RUNNING.toString()
					: SpiderStatus.STOPPED.toString());
			break;
		case VIEW_RESULTS:
			try {
				int start = this.getParam(params, PARAM_START, 1);
				if (start <= 0) {
					start = 1;
				}
				final int count = this.getParam(params, PARAM_COUNT, 0);
				final boolean hasEnd = count > 0;
				final int finalRecord = !hasEnd ? 0 : (start > 0 ? start + count - 1 : count);

				final ApiResponseList resultList = new ApiResponseList(name);
				for (int i = start - 1, recordsProcessed = i; i < historyReferences.size(); ++i) {
					HistoryReference historyReference = historyReferences.get(i);
					resultList.addItem(httpMessageToSet(historyReference.getHistoryId(), historyReference.getHttpMessage()));

					if (hasEnd) {
						++recordsProcessed;
						if (recordsProcessed >= finalRecord) {
							break;
						}
					}
				}
				result = resultList;
			} catch (SQLException | IOException e) {
				throw new ApiException(ApiException.Type.INTERNAL_ERROR, e);
			}
			break;
		case VIEW_NUMBER_OF_RESULTS:
			result = new ApiResponseElement(name, String.valueOf(historyReferences.size()));
			break;
		default:
			throw new ApiException(ApiException.Type.BAD_VIEW);
		}
		return result;
	}

	private boolean isSpiderRunning() {
		return (extension.isSpiderRunning() && spiderThread != null);
	}

	private void stopSpider() {
		if (isSpiderRunning()) {
			spiderThread.stopSpider();
			spiderThread = null;
		}
	}

	// Copied from ZAP core class ApiResponseConversionUtils
	// XXX Remove once new ZAP core release is available.
	private static ApiResponseSet httpMessageToSet(int historyId, HttpMessage msg) {
		Map<String, String> map = new HashMap<>();
		map.put("id", String.valueOf(historyId));
		map.put("cookieParams", msg.getCookieParamsAsString());
		map.put("note", msg.getNote());
		map.put("requestHeader", msg.getRequestHeader().toString());
		map.put("requestBody", msg.getRequestBody().toString());
		map.put("responseHeader", msg.getResponseHeader().toString());

		if (HttpHeader.GZIP.equals(msg.getResponseHeader().getHeader(HttpHeader.CONTENT_ENCODING))) {
			// Uncompress gziped content
			try (ByteArrayInputStream bais = new ByteArrayInputStream(msg.getResponseBody().getBytes());
				 GZIPInputStream gis = new GZIPInputStream(bais);
				 InputStreamReader isr = new InputStreamReader(gis);
				 BufferedReader br = new BufferedReader(isr);) {
				StringBuilder sb = new StringBuilder();
				String line = null;
				while ((line = br.readLine()) != null) {
					sb.append(line);
				}
				map.put("responseBody", sb.toString());
			} catch (IOException e) {
				logger.error("Unable to uncompress gzip content: " + e.getMessage(), e);
				map.put("responseBody", msg.getResponseBody().toString());
			}
		} else {
			map.put("responseBody", msg.getResponseBody().toString());
		}

		return new ApiResponseSet("message", map);
	}

	@Override
	public void spiderStarted() {
		historyReferences = new ArrayList<>();
	}

	@Override
	public void foundMessage(HistoryReference historyReference, HttpMessage httpMessage) {
		historyReferences.add(historyReference);
	}

	@Override
	public void spiderStopped() {
	}

	void reset() {
		stopSpider();
		historyReferences = Collections.emptyList();
	}
}
