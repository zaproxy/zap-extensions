package org.zaproxy.zap.extension.foxhound.taint;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

public class TaintRange {

    private int begin;
    private int end;

    private List<TaintOperation> flow;

    // Derived Fields
    private TaintOperation sink;
    private Set<TaintOperation> sources;

    public TaintRange(int begin, int end, List<TaintOperation> flow) {
        this.begin = begin;
        this.end = end;
        this.flow = flow;
    }

    public TaintRange() {
        this.flow = new ArrayList<>();
        this.sources = new HashSet<>();
    }

    public int getBegin() {
        return begin;
    }

    public void setBegin(int begin) {
        this.begin = begin;
    }

    public int getEnd() {
        return end;
    }

    public void setEnd(int end) {
        this.end = end;
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
}
