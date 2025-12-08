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
package org.zaproxy.zap.extension.foxhound.db;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;
import org.zaproxy.zap.extension.foxhound.taint.TaintInfo;
import org.zaproxy.zap.extension.foxhound.taint.TaintOperation;

public class TaintInfoFilter {

    private final Set<String> activeSources;
    private final Set<String> activeSinks;

    public TaintInfoFilter() {
        this.activeSources = new HashSet<>();
        this.activeSinks = new HashSet<>();
    }

    public boolean matches(TaintInfo taintInfo) {
        boolean sourceMatch =
                activeSources.isEmpty()
                        || !Collections.disjoint(
                                taintInfo.getSources().stream()
                                        .map(TaintOperation::getOperation)
                                        .collect(Collectors.toSet()),
                                activeSources);
        boolean sinkMatch =
                activeSinks.isEmpty() || activeSinks.contains(taintInfo.getSink().getOperation());
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
