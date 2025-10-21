package org.zaproxy.zap.extension.foxhound.taint;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

public class TaintInfo {

    private String str;
    private String location;
    private String parentLocation;
    private String referrer;
    private String sinkName;
    private long timeStamp;
    private String cookie;
    private boolean subframe;

    private List<TaintRange> taintRanges;

    // Derived Fields
    private TaintOperation sink;
    private Set<TaintOperation> sources;

    public TaintInfo(List<TaintRange> taintRanges, String cookie, long timeStamp, String sinkName, String referrer, String parentLocation, String location, String str) {
        this.taintRanges = taintRanges;
        this.cookie = cookie;
        this.timeStamp = timeStamp;
        this.sinkName = sinkName;
        this.referrer = referrer;
        this.parentLocation = parentLocation;
        this.location = location;
        this.str = str;
    }

    public TaintInfo() {
        taintRanges = new ArrayList<>();
        sources = new HashSet<>();
    }

    public String getStr() {
        return str;
    }

    public void setStr(String str) {
        this.str = str;
    }

    public String getLocation() {
        return location;
    }

    public void setLocation(String location) {
        this.location = location;
    }

    public String getParentLocation() {
        return parentLocation;
    }

    public void setParentLocation(String parentLocation) {
        this.parentLocation = parentLocation;
    }

    public String getReferrer() {
        return referrer;
    }

    public void setReferrer(String referrer) {
        this.referrer = referrer;
    }

    public String getSinkName() {
        return sinkName;
    }

    public void setSinkName(String sinkName) {
        this.sinkName = sinkName;
    }

    public long getTimeStamp() {
        return timeStamp;
    }

    public void setTimeStamp(long timeStamp) {
        this.timeStamp = timeStamp;
    }

    public String getCookie() {
        return cookie;
    }

    public void setCookie(String cookie) {
        this.cookie = cookie;
    }

    public List<TaintRange> getTaintRanges() {
        return taintRanges;
    }

    public void setTaintRanges(List<TaintRange> taintRanges) {
        this.taintRanges = taintRanges;
    }

    public boolean isSubframe() {
        return subframe;
    }

    public void setSubframe(boolean subframe) {
        this.subframe = subframe;
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
        if (!(object instanceof TaintInfo taintInfo)) return false;
        return timeStamp == taintInfo.timeStamp && subframe == taintInfo.subframe && Objects.equals(str, taintInfo.str) && Objects.equals(location, taintInfo.location) && Objects.equals(parentLocation, taintInfo.parentLocation) && Objects.equals(referrer, taintInfo.referrer) && Objects.equals(sinkName, taintInfo.sinkName) && Objects.equals(cookie, taintInfo.cookie) && Objects.equals(taintRanges, taintInfo.taintRanges);
    }

    @Override
    public int hashCode() {
        return Objects.hash(str, location, parentLocation, referrer, sinkName, timeStamp, cookie, subframe, taintRanges);
    }

    @Override
    public String toString() {
        return "TaintInfo{" +
                "str='" + str + '\'' +
                ", location='" + location + '\'' +
                ", parentLocation='" + parentLocation + '\'' +
                ", referrer='" + referrer + '\'' +
                ", sinkName='" + sinkName + '\'' +
                ", timeStamp=" + timeStamp +
                ", cookie='" + cookie + '\'' +
                ", subframe=" + subframe +
                ", taintRanges=" + taintRanges +
                ", sink=" + sink +
                ", sources=" + sources +
                '}';
    }
}
