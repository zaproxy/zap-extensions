package org.zaproxy.zap.extension.foxhound.db;

import org.zaproxy.zap.extension.foxhound.FoxhoundEventPublisher;
import org.zaproxy.zap.extension.foxhound.taint.TaintDeserializer;
import org.zaproxy.zap.extension.foxhound.taint.TaintInfo;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class TaintInfoStore {

    private Map<Integer, TaintInfo> taintInfoList = new ConcurrentHashMap<>();;
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
            FoxhoundEventPublisher.publishEvent(FoxhoundEventPublisher.TAINT_INFO_CREATED, taintInfo, null);
        }
    }

    public void clearAll() {
        taintInfoList.clear();
        FoxhoundEventPublisher.publishClearEvent();
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
