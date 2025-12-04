/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
package org.zaproxy.zap.extension.foxhound;

import java.util.HashMap;
import java.util.Map;
import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.eventBus.Event;
import org.zaproxy.zap.eventBus.EventPublisher;
import org.zaproxy.zap.extension.foxhound.taint.TaintInfo;

public class FoxhoundEventPublisher implements EventPublisher {

    private static FoxhoundEventPublisher publisher = null;

    public static final String TAINT_INFO_CREATED = "taintinfo.created";
    public static final String TAINT_INFO_UPDATED = "taintinfo.updated";
    public static final String TAINT_INFO_CLEARED = "taintinfo.cleared";

    public static final String JOB_ID = "jobId";

    public static synchronized FoxhoundEventPublisher getPublisher() {
        if (publisher == null) {
            publisher = new FoxhoundEventPublisher();
            ZAP.getEventBus()
                    .registerPublisher(
                            publisher, TAINT_INFO_CREATED, TAINT_INFO_UPDATED, TAINT_INFO_CLEARED);
        }
        return publisher;
    }

    public static void publishEvent(
            String eventName, TaintInfo info, Map<String, String> parameters) {
        Map<String, String> map = new HashMap<>();
        if (parameters != null && !parameters.isEmpty()) {
            map.putAll(parameters);
        }
        map.put(JOB_ID, Integer.toString(info.getId()));

        Event event = new Event(getPublisher(), eventName, null, map);

        ZAP.getEventBus().publishSyncEvent(getPublisher(), event);
    }

    public static void publishClearEvent() {
        ZAP.getEventBus()
                .publishSyncEvent(
                        getPublisher(), new Event(getPublisher(), TAINT_INFO_CLEARED, null));
    }

    @Override
    public String getPublisherName() {
        return FoxhoundEventPublisher.class.getCanonicalName();
    }
}
