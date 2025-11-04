package org.zaproxy.zap.extension.foxhound.taint;

public interface TaintStoreEventListener {

    public void taintInfoAdded(TaintInfo taintInfo);

}
