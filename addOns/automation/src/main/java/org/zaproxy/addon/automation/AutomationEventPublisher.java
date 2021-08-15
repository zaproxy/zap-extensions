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

import java.util.HashMap;
import java.util.Map;
import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.eventBus.Event;
import org.zaproxy.zap.eventBus.EventPublisher;

public class AutomationEventPublisher implements EventPublisher {

    private static AutomationEventPublisher publisher = null;

    /** Indicates that a plan has started to run. */
    public static final String PLAN_CREATED = "plan.created";

    public static final String PLAN_STARTED = "plan.started";

    public static final String PLAN_ENV_CREATED = "plan.env.created";

    public static final String PLAN_FINISHED = "plan.finished";

    public static final String PLAN_ERROR_MESSAGE = "plan.error";

    public static final String PLAN_WARNING_MESSAGE = "plan.warning";

    public static final String PLAN_INFO_MESSAGE = "plan.info";

    public static final String PLAN_CHANGED = "plan.changed";

    public static final String PLAN_SAVED = "plan.saved";

    public static final String JOB_STARTED = "job.started";

    public static final String JOB_FINISHED = "job.finished";

    public static final String JOB_ADDED = "job.added";

    public static final String JOB_CHANGED = "job.changed";

    public static final String JOB_REMOVED = "job.removed";

    public static final String TEST_ADDED = "test.added";

    public static final String TEST_REMOVED = "test.removed";

    public static final String JOB_ID = "jobId";
    public static final String JOB_NAME = "jobName";
    public static final String JOB_TYPE = "jobType";
    public static final String PLAN_ID = "planId";
    public static final String MESSAGE = "message";

    @Override
    public String getPublisherName() {
        return AutomationEventPublisher.class.getCanonicalName();
    }

    public static synchronized AutomationEventPublisher getPublisher() {
        if (publisher == null) {
            publisher = new AutomationEventPublisher();
            ZAP.getEventBus()
                    .registerPublisher(
                            publisher,
                            PLAN_CREATED,
                            PLAN_STARTED,
                            PLAN_ENV_CREATED,
                            PLAN_FINISHED,
                            PLAN_ERROR_MESSAGE,
                            PLAN_WARNING_MESSAGE,
                            PLAN_INFO_MESSAGE,
                            PLAN_CHANGED,
                            PLAN_SAVED,
                            JOB_STARTED,
                            JOB_FINISHED,
                            JOB_ADDED,
                            JOB_CHANGED,
                            JOB_REMOVED,
                            TEST_ADDED,
                            TEST_REMOVED);
        }
        return publisher;
    }

    public static void publishMessageEvent(String event, String msg) {
        Map<String, String> map = new HashMap<>();
        map.put(MESSAGE, msg);

        ZAP.getEventBus()
                .publishSyncEvent(getPublisher(), new Event(getPublisher(), event, null, map));
    }

    public static void publishEvent(
            String event, AutomationJob job, Map<String, String> parameters) {
        Map<String, String> map = new HashMap<>();
        if (parameters != null && !parameters.isEmpty()) {
            map.putAll(parameters);
        }
        map.put(JOB_NAME, job.getName());
        map.put(JOB_TYPE, job.getType());
        map.put(JOB_ID, Integer.toString(job.getPlan().getJobIndex(job)));

        publishEvent(event, job.getPlan(), map);
    }

    public static void publishEvent(
            String event, AutomationPlan plan, Map<String, String> parameters) {
        Map<String, String> map = new HashMap<>();
        if (parameters != null && !parameters.isEmpty()) {
            map.putAll(parameters);
        }
        map.put(PLAN_ID, Integer.toString(plan.getId()));

        ZAP.getEventBus()
                .publishSyncEvent(getPublisher(), new Event(getPublisher(), event, null, map));
    }
}
