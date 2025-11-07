package org.zaproxy.zap.extension.foxhound;

import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.eventBus.Event;
import org.zaproxy.zap.eventBus.EventPublisher;
import org.zaproxy.zap.extension.foxhound.taint.TaintInfo;

import java.util.HashMap;
import java.util.Map;

public class FoxhoundEventPublisher implements EventPublisher {

    private static FoxhoundEventPublisher publisher = null;

    public static final String TAINT_INFO_CREATED = "taintinfo.created";
    public static final String TAINT_INFO_UPDATED = "taintinfo.updated";

    public static final String JOB_ID = "jobId";

    public static synchronized FoxhoundEventPublisher getPublisher() {
        if (publisher == null) {
            publisher = new FoxhoundEventPublisher();
            ZAP.getEventBus()
                    .registerPublisher(
                            publisher,
                            TAINT_INFO_CREATED,
                            TAINT_INFO_UPDATED);
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

        Event event = new Event(
                getPublisher(), eventName, null, map
        );

        ZAP.getEventBus()
                .publishSyncEvent(getPublisher(), event);
    }

    @Override
    public String getPublisherName() {
        return FoxhoundEventPublisher.class.getCanonicalName();
    }

}
