package org.zaproxy.zap.extension.foxhound.db;

import org.zaproxy.zap.extension.foxhound.taint.TaintInfo;
import org.zaproxy.zap.extension.foxhound.taint.TaintOperation;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

public class TaintInfoFilter{

    private final Set<String> activeSources;
    private final Set<String> activeSinks;

    public TaintInfoFilter() {
        this.activeSources = new HashSet<>();
        this.activeSinks = new HashSet<>();
    }

    public boolean matches(TaintInfo taintInfo) {
        boolean sourceMatch = activeSources.isEmpty() ||
                !Collections.disjoint(taintInfo.getSources().stream().map(TaintOperation::getOperation).collect(Collectors.toSet()), activeSources);
        boolean sinkMatch = activeSinks.isEmpty() || activeSinks.contains(taintInfo.getSink().getOperation());
        return sourceMatch && sinkMatch;
    }

    public Set<String> getActiveSources() {
        return activeSources;
    }

    public Set<String> getActiveSinks() {
        return activeSinks;
    }

    public void setSources(Collection<String> sourceNames) {
        activeSources.clear();
        activeSources.addAll(sourceNames);
    }

    public void setSinks(Collection<String> sinkNames) {
        activeSinks.clear();
        activeSinks.addAll(sinkNames);
    }

    public void reset() {
        activeSinks.clear();
        activeSources.clear();
    }

}
