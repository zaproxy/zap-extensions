/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.foxhound.taint;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

public class TaintInfo implements SourceSinkProvider, TaintLocationProvider {

    private int id = -1;
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

    public TaintInfo(
            List<TaintRange> taintRanges,
            String cookie,
            long timeStamp,
            String sinkName,
            String referrer,
            String parentLocation,
            String location,
            String str) {
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

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getStr() {
        return str;
    }

    public void setStr(String str) {
        this.str = str;
    }

    @Override
    public TaintLocation getLocation() {
        return getSink().getLocation();
    }

    public String getLocationName() {
        return location;
    }

    public void setLocationName(String location) {
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
        if (!(object instanceof TaintInfo taintInfo)) return false;
        return timeStamp == taintInfo.timeStamp
                && subframe == taintInfo.subframe
                && Objects.equals(str, taintInfo.str)
                && Objects.equals(location, taintInfo.location)
                && Objects.equals(parentLocation, taintInfo.parentLocation)
                && Objects.equals(referrer, taintInfo.referrer)
                && Objects.equals(sinkName, taintInfo.sinkName)
                && Objects.equals(cookie, taintInfo.cookie)
                && Objects.equals(taintRanges, taintInfo.taintRanges);
    }

    @Override
    public int hashCode() {
        return Objects.hash(
                str,
                location,
                parentLocation,
                referrer,
                sinkName,
                timeStamp,
                cookie,
                subframe,
                taintRanges);
    }

    @Override
    public String toString() {
        return "Taint flow: " + getSourceSinkLabel() + " from " + getSink().getLocation();
    }
}
