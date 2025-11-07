package org.zaproxy.zap.extension.foxhound.taint;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

public class TaintRange extends Range implements TaintLocationProvider, SourceSinkProvider {

    private String str;
    private List<TaintOperation> flow;

    // Derived Fields
    private TaintOperation sink;
    private Set<TaintOperation> sources;

    public TaintRange(String str, int begin, int end, List<TaintOperation> flow) {
        super(begin, end);
        this.flow = flow;
        this.str = str;
    }

    public TaintRange() {
        this.flow = new ArrayList<>();
        this.sources = new HashSet<>();
        this.str = "";
    }

    public String getStr() {
        return str;
    }

    public void setStr(String str) {
        this.str = str;
    }

    public List<TaintOperation> getFlow() {
        return flow;
    }

    public void setFlow(List<TaintOperation> flow) {
        this.flow = flow;
    }

    @Override
    public TaintOperation getSink() {
        return sink;
    }

    public void setSink(TaintOperation sink) {
        this.sink = sink;
    }

    @Override
    public Set<TaintOperation> getSources() {
        return sources;
    }

    public String getSourceSinkLabel() {
        return SourceSinkUtils.getSourceSinkLabel(this);
    }

    @Override
    public boolean equals(Object object) {
        if (!(object instanceof TaintRange that)) return false;
        return begin == that.begin && end == that.end && Objects.equals(flow, that.flow);
    }

    @Override
    public int hashCode() {
        return Objects.hash(begin, end, flow);
    }

    @Override
    public String toString() {
        return "Taint flow: " + getSourceSinkLabel() + " from " + getSink().getLocation();
    }

    @Override
    public TaintLocation getLocation() {
        return getSink().getLocation();
    }
}
