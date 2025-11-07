package org.zaproxy.zap.extension.foxhound.db;

import org.htmlunit.jetty.util.ConcurrentHashSet;
import org.zaproxy.zap.extension.foxhound.FoxhoundEventPublisher;
import org.zaproxy.zap.extension.foxhound.pipeline.Consumer;
import org.zaproxy.zap.extension.foxhound.taint.TaintDeserializer;
import org.zaproxy.zap.extension.foxhound.taint.TaintInfo;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

public class TaintInfoStore {

    private Map<Integer, TaintInfo> taintInfoList = new ConcurrentHashMap<>();;
    private boolean changed = false;
    private int nextInt = 0;

    public TaintInfoStore() {

    }

    public void addTaintInfo(TaintInfo taintInfo) {
        try {
            if (taintInfo.getId() < 0) {
                taintInfo.setId(nextInt++);
            }
            taintInfoList.put(taintInfo.getId(), taintInfo);
        } finally {
            this.changed = true;
            FoxhoundEventPublisher.publishEvent(FoxhoundEventPublisher.TAINT_INFO_CREATED, taintInfo, null);
        }
    }

    public TaintInfo getTaintInfo(int id) {
        return taintInfoList.get(id);
    }

    public void deserializeAndAddTaintInfo(String s) {
        TaintInfo info = TaintDeserializer.deserializeTaintInfo(s);
        if (info != null) {
            addTaintInfo(info);
        }
    }


}
