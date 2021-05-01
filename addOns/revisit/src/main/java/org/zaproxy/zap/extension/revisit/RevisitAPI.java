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
package org.zaproxy.zap.extension.revisit;

import java.text.ParseException;
import java.util.Date;
import net.sf.json.JSONObject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.zap.extension.api.ApiAction;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.extension.api.ApiException.Type;
import org.zaproxy.zap.extension.api.ApiImplementor;
import org.zaproxy.zap.extension.api.ApiResponse;
import org.zaproxy.zap.extension.api.ApiResponseElement;
import org.zaproxy.zap.extension.api.ApiResponseList;
import org.zaproxy.zap.extension.api.ApiView;
import org.zaproxy.zap.users.User;

/** The API for manipulating {@link User Users}. */
public class RevisitAPI extends ApiImplementor {

    private static final Logger log = LogManager.getLogger(RevisitAPI.class);

    private static final String PREFIX = "revisit";

    private static final String VIEW_REVISIT_LIST = "revisitList";

    private static final String ACTION_REVISIT_SITE_ON = "revisitSiteOn";
    private static final String ACTION_REVISIT_SITE_OFF = "revisitSiteOff";

    private static final String PARAM_SITE = "site";
    private static final String PARAM_START_TIME = "startTime";
    private static final String PARAM_END_TIME = "endTime";

    private ExtensionRevisit extension;

    /** Provided only for API client generator usage. */
    public RevisitAPI() {
        this(null);
    }

    public RevisitAPI(ExtensionRevisit extension) {
        super();
        this.extension = extension;

        this.addApiView(new ApiView(VIEW_REVISIT_LIST));

        this.addApiAction(
                new ApiAction(
                        ACTION_REVISIT_SITE_ON,
                        new String[] {PARAM_SITE, PARAM_START_TIME, PARAM_END_TIME}));
        this.addApiAction(new ApiAction(ACTION_REVISIT_SITE_OFF, new String[] {PARAM_SITE}));
    }

    @Override
    public String getPrefix() {
        return PREFIX;
    }

    @Override
    public ApiResponse handleApiView(String name, JSONObject params) throws ApiException {
        log.debug("handleApiView {} {}", name, params);

        switch (name) {
            case VIEW_REVISIT_LIST:
                ApiResponseList listResponse = new ApiResponseList(name);
                for (String site : extension.getSites()) {
                    listResponse.addItem(new ApiResponseElement("site", site));
                }
                return listResponse;

            default:
                throw new ApiException(ApiException.Type.BAD_VIEW);
        }
    }

    @Override
    public ApiResponse handleApiAction(String name, JSONObject params) throws ApiException {
        log.debug("handleApiAction {} {}", name, params);

        switch (name) {
            case ACTION_REVISIT_SITE_ON:
                Date startDate;
                Date endDate;
                try {
                    startDate =
                            ExtensionRevisit.dateFormat.parse(
                                    this.getParam(params, PARAM_START_TIME, ""));
                    endDate =
                            ExtensionRevisit.dateFormat.parse(
                                    this.getParam(params, PARAM_END_TIME, ""));
                    this.extension.setEnabledForSite(
                            this.getParam(params, PARAM_SITE, ""), startDate, endDate);
                    return ApiResponseElement.OK;
                } catch (ParseException e) {
                    throw new ApiException(
                            Type.ILLEGAL_PARAMETER,
                            "Expected date format: " + ExtensionRevisit.dateFormat.toString());
                }

            case ACTION_REVISIT_SITE_OFF:
                this.extension.unsetEnabledForSite(this.getParam(params, PARAM_SITE, ""));
                return ApiResponseElement.OK;

            default:
                throw new ApiException(Type.BAD_ACTION);
        }
    }
}
