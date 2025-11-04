package org.zaproxy.zap.extension.foxhound.taint;

import javax.naming.ldap.HasControls;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class TaintInfoStore {

    private final Set<TaintInfo> taintInfos = new HashSet<>();
    private final List<TaintStoreEventListener> listeners = new ArrayList<>();

    public TaintInfoStore() {

    }

    public void registerEventListener(TaintStoreEventListener listener) {
        listeners.add(listener);
    }

    public void addTaintInfo(TaintInfo taintInfo) {
        if (!taintInfos.contains(taintInfo)) {
            taintInfos.add(taintInfo);
            for (TaintStoreEventListener listener : listeners) {
                listener.taintInfoAdded(taintInfo);
            }
        }
    }

}
