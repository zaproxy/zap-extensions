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
