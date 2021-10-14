/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.addon.automation;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import net.sf.json.JSONObject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.automation.jobs.DelayJob;
import org.zaproxy.zap.extension.api.ApiAction;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.extension.api.ApiException.Type;
import org.zaproxy.zap.extension.api.ApiImplementor;
import org.zaproxy.zap.extension.api.ApiResponse;
import org.zaproxy.zap.extension.api.ApiResponseElement;
import org.zaproxy.zap.extension.api.ApiResponseList;
import org.zaproxy.zap.extension.api.ApiResponseSet;
import org.zaproxy.zap.extension.api.ApiView;
import org.zaproxy.zap.utils.ApiUtils;

public class AutomationAPI extends ApiImplementor {

    private static final Logger LOG = LogManager.getLogger(AutomationAPI.class);

    private static final String PREFIX = "automation";

    private static final String ACTION_RUN_PLAN = "runPlan";
    private static final String ACTION_END_DELAY_JOB = "endDelayJob";
    private static final String VIEW_PLAN_PROGRESS = "planProgress";

    private static final String PARAM_FILE_PATH = "filePath";
    private static final String PARAM_PLAN_ID = "planId";

    private static final String ELEMENT_INFO = "info";
    private static final String ELEMENT_WARN = "warn";
    private static final String ELEMENT_ERROR = "error";

    private ExtensionAutomation extension;

    /** Provided only for API client generator usage. */
    public AutomationAPI() {
        this(null);
    }

    public AutomationAPI(ExtensionAutomation extension) {
        super();
        this.extension = extension;
        this.addApiAction(new ApiAction(ACTION_RUN_PLAN, new String[] {PARAM_FILE_PATH}));
        this.addApiAction(new ApiAction(ACTION_END_DELAY_JOB));
        this.addApiView(new ApiView(VIEW_PLAN_PROGRESS, new String[] {PARAM_PLAN_ID}));
    }

    @Override
    public String getPrefix() {
        return PREFIX;
    }

    @Override
    public ApiResponse handleApiAction(String name, JSONObject params) throws ApiException {
        LOG.debug("handleApiAction {} {}", name, params);

        if (name.equals(ACTION_RUN_PLAN)) {
            try {
                AutomationPlan plan =
                        extension.loadPlan(
                                new File(ApiUtils.getNonEmptyStringParam(params, PARAM_FILE_PATH)));
                extension.registerPlan(plan);

                if (View.isInitialised()) {
                    extension.displayPlan(plan);
                }
                extension.runPlanAsync(plan);

                return new ApiResponseElement(PARAM_PLAN_ID, Integer.toString(plan.getId()));
            } catch (IOException | ApiException e) {
                throw new ApiException(Type.DOES_NOT_EXIST, e.getMessage());
            }
        } else if (name.equals(ACTION_END_DELAY_JOB)) {
            DelayJob.setEndJob(true);
            return ApiResponseElement.OK;
        }
        throw new ApiException(Type.BAD_ACTION);
    }

    @Override
    public ApiResponse handleApiView(String name, JSONObject params) throws ApiException {
        LOG.debug("handleApiView {} {}", name, params);

        if (name.equals(VIEW_PLAN_PROGRESS)) {
            AutomationPlan plan = extension.getPlan(params.getInt(PARAM_PLAN_ID));

            if (plan == null) {
                throw new ApiException(Type.DOES_NOT_EXIST);
            }

            return progressResponse(plan);
        }
        throw new ApiException(Type.BAD_VIEW);
    }

    ApiResponse progressResponse(AutomationPlan plan) {
        HashMap<String, Object> map = new HashMap<>();
        map.put(PARAM_PLAN_ID, plan.getId());

        if (plan.getStarted() != null) {
            map.put("started", plan.getStarted());
        }
        if (plan.getFinished() != null) {
            map.put("finished", plan.getFinished());
        }

        ApiResponseList infoMsgs = new ApiResponseList(ELEMENT_INFO);
        plan.getProgress().getInfos().stream()
                .map(msg -> new ApiResponseElement(ELEMENT_INFO, msg))
                .forEach(infoMsgs::addItem);
        map.put(ELEMENT_INFO, infoMsgs);

        ApiResponseList warnMsgs = new ApiResponseList(ELEMENT_WARN);
        plan.getProgress().getWarnings().stream()
                .map(msg -> new ApiResponseElement(ELEMENT_WARN, msg))
                .forEach(warnMsgs::addItem);
        map.put(ELEMENT_WARN, warnMsgs);

        ApiResponseList errorMsgs = new ApiResponseList(ELEMENT_ERROR);
        plan.getProgress().getErrors().stream()
                .map(msg -> new ApiResponseElement(ELEMENT_ERROR, msg))
                .forEach(errorMsgs::addItem);
        map.put(ELEMENT_ERROR, errorMsgs);

        return new ApiResponseSet<>(VIEW_PLAN_PROGRESS, map);
    }
}
