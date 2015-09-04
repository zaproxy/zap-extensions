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
 *   http://www.apache.org/licenses/LICENSE-2.0 
 *   
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS, 
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
 * See the License for the specific language governing permissions and 
 * limitations under the License. 
 */
package org.zaproxy.zap.extension.alertFilters;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import net.sf.json.JSONObject;

import org.apache.log4j.Logger;
import org.zaproxy.zap.extension.api.ApiAction;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.extension.api.ApiException.Type;
import org.zaproxy.zap.extension.api.ApiImplementor;
import org.zaproxy.zap.extension.api.ApiResponse;
import org.zaproxy.zap.extension.api.ApiResponseElement;
import org.zaproxy.zap.extension.api.ApiResponseList;
import org.zaproxy.zap.extension.api.ApiResponseSet;
import org.zaproxy.zap.extension.api.ApiView;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.users.User;
import org.zaproxy.zap.utils.ApiUtils;

/**
 * The API for manipulating {@link User Users}.
 */
public class AlertFilterAPI extends ApiImplementor {

	private static final Logger log = Logger.getLogger(AlertFilterAPI.class);

	private static final String PREFIX = "alertFilter";

	private static final String VIEW_ALERT_FILTER_LIST = "alertFilterList";

	private static final String ACTION_ADD_ALERT_FILTER = "addAlertFilter";
	private static final String ACTION_REMOVE_ALERT_FILTER = "removeAlertFilter";

	private static final String PARAM_CONTEXT_ID = "contextId";
	private static final String PARAM_RULE_ID = "ruleId";
	private static final String PARAM_NEW_LEVEL = "newLevel";
	private static final String PARAM_URL = "url";
	private static final String PARAM_URL_IS_REGEX = "urlIsRegex";
	private static final String PARAM_PARAMETER = "parameter";
	private static final String PARAM_ENABLED = "enabled";

	private ExtensionAlertFilters extension;

	public AlertFilterAPI(ExtensionAlertFilters extension) {
		super();
		this.extension = extension;

		this.addApiView(new ApiView(VIEW_ALERT_FILTER_LIST, null, new String[] { PARAM_CONTEXT_ID }));

		this.addApiAction(new ApiAction(ACTION_ADD_ALERT_FILTER, 
				new String[] { PARAM_CONTEXT_ID, PARAM_RULE_ID, PARAM_NEW_LEVEL },
				new String[] { PARAM_URL, PARAM_URL_IS_REGEX, PARAM_PARAMETER, PARAM_ENABLED}));
		this.addApiAction(new ApiAction(ACTION_REMOVE_ALERT_FILTER, 
				new String[] { PARAM_CONTEXT_ID, PARAM_RULE_ID, PARAM_NEW_LEVEL },
				new String[] { PARAM_URL, PARAM_URL_IS_REGEX, PARAM_PARAMETER, PARAM_ENABLED}));

	}

	@Override
	public String getPrefix() {
		return PREFIX;
	}

	@Override
	public ApiResponse handleApiView(String name, JSONObject params) throws ApiException {
		log.debug("handleApiView " + name + " " + params.toString());
		Context context;

		switch (name) {
		case VIEW_ALERT_FILTER_LIST:
			ApiResponseList listResponse = new ApiResponseList(name);
			context = ApiUtils.getContextByParamId(params, PARAM_CONTEXT_ID);
			List<AlertFilter> afs = extension.getContextAlertFilterManager(
					context.getIndex()).getAlertFilters();
			
			for (AlertFilter af : afs) {
				listResponse.addItem(buildResponseFromAlertFilter(af));
			}
			return listResponse;

		default:
			throw new ApiException(ApiException.Type.BAD_VIEW);
		}
	}

	@Override
	public ApiResponse handleApiAction(String name, JSONObject params) throws ApiException {
		log.debug("handleApiAction " + name + " " + params.toString());

		AlertFilter af; 
		Context context;
		switch (name) {
		case ACTION_ADD_ALERT_FILTER:
			context = ApiUtils.getContextByParamId(params, PARAM_CONTEXT_ID);
			af = new AlertFilter(context.getIndex(), 
					ApiUtils.getIntParam(params, PARAM_RULE_ID), 
					ApiUtils.getIntParam(params, PARAM_NEW_LEVEL), 
					ApiUtils.getOptionalStringParam(params, PARAM_URL),
					getParam(params, PARAM_URL_IS_REGEX, false),
					ApiUtils.getOptionalStringParam(params, PARAM_PARAMETER),
					getParam(params, PARAM_ENABLED, true));
			
			// TODO more validation, esp url!
			extension.getContextAlertFilterManager(context.getIndex()).addAlertFilter(af);
			return ApiResponseElement.OK;
		case ACTION_REMOVE_ALERT_FILTER:
			context = ApiUtils.getContextByParamId(params, PARAM_CONTEXT_ID);
			af = new AlertFilter(context.getIndex(), 
					ApiUtils.getIntParam(params, PARAM_RULE_ID), 
					ApiUtils.getIntParam(params, PARAM_NEW_LEVEL), 
					ApiUtils.getOptionalStringParam(params, PARAM_URL),
					getParam(params, PARAM_URL_IS_REGEX, false),
					ApiUtils.getOptionalStringParam(params, PARAM_PARAMETER),
					getParam(params, PARAM_ENABLED, true));
			if (extension.getContextAlertFilterManager(
					context.getIndex()).removeAlertFilter(af)) {
				return ApiResponseElement.OK;
			}

			return ApiResponseElement.FAIL;

		default:
			throw new ApiException(Type.BAD_ACTION);
		}

	}
	
	/**
	 * Builds the response describing an AlertFilter
	 * 
	 * @param af the AlertFilter
	 * @return the api response
	 */
	private ApiResponse buildResponseFromAlertFilter(AlertFilter af) {
		Map<String, String> fields = new HashMap<>();
		fields.put(PARAM_CONTEXT_ID, Integer.toString(af.getContextId()));
		fields.put(PARAM_RULE_ID, Integer.toString(af.getRuleId()));
		fields.put(PARAM_NEW_LEVEL, Integer.toString(af.getNewRisk()));
		fields.put(PARAM_URL, af.getUrl());
		fields.put(PARAM_URL_IS_REGEX, Boolean.toString(af.isRegex()));
		fields.put(PARAM_PARAMETER, af.getParameter());
		fields.put(PARAM_ENABLED, Boolean.toString(af.isEnabled()));
		ApiResponseSet response = new ApiResponseSet("alertFilter", fields);
		return response;
	}
}
