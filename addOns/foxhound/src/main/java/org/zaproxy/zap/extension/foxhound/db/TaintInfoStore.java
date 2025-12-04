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

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.zaproxy.zap.extension.foxhound.FoxhoundEventPublisher;
import org.zaproxy.zap.extension.foxhound.taint.TaintDeserializer;
import org.zaproxy.zap.extension.foxhound.taint.TaintInfo;

public class TaintInfoStore {

    private Map<Integer, TaintInfo> taintInfoList = new ConcurrentHashMap<>();
    ;
    private int nextInt = 0;

    public TaintInfoStore() {}

    public void addTaintInfo(TaintInfo taintInfo) {
        try {
            if (taintInfo.getId() < 0) {
                taintInfo.setId(nextInt++);
            }
            taintInfoList.put(taintInfo.getId(), taintInfo);
        } finally {
            FoxhoundEventPublisher.publishEvent(
                    FoxhoundEventPublisher.TAINT_INFO_CREATED, taintInfo, null);
        }
    }

    public void clearAll() {
        taintInfoList.clear();
        FoxhoundEventPublisher.publishClearEvent();
    }

    public TaintInfo getTaintInfo(int id) {
        return taintInfoList.get(id);
    }

    public List<TaintInfo> getFilteredTaintInfos(TaintInfoFilter filter) {
        List<TaintInfo> filteredList = new ArrayList<>();
        for (TaintInfo t : taintInfoList.values()) {
            if (filter.matches(t)) {
                filteredList.add(t);
            }
        }
        return filteredList;
    }

    public void deserializeAndAddTaintInfo(String s) {
        TaintInfo info = TaintDeserializer.deserializeTaintInfo(s);
        if (info != null) {
            addTaintInfo(info);
        }
    }
}
