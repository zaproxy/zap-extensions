package org.zaproxy.zap.extension.foxhound.taint;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import static org.zaproxy.zap.extension.foxhound.taint.TaintInfo.getOperationNameList;

public class TaintRange extends Range implements TaintLocationProvider {

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

    public String getSourceSinkLabel() {
        return getOperationNameList(sources) + "  \u2192 " + sink.getOperation();
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

    public TaintOperation getSink() {
        return sink;
    }

    public void setSink(TaintOperation sink) {
        this.sink = sink;
    }

    public Set<TaintOperation> getSources() {
        return sources;
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
        return "TaintRange{" +
                "begin=" + begin +
                ", end=" + end +
                ", flow=" + flow +
                ", sink=" + sink +
                ", sources=" + sources +
                '}';
    }

    @Override
    public TaintLocation getLocation() {
        return getSink().getLocation();
    }
}
