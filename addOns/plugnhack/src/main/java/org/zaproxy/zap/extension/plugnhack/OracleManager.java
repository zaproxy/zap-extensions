/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2013 The ZAP Development Team
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
package org.zaproxy.zap.extension.plugnhack;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class OracleManager {

    private Map<Integer, Map<String, String>> oracleMap = new HashMap<>();
    private List<OracleListener> listeners = new ArrayList<>();

    private int id = 0;

    public int registerOracle(Map<String, String> data) {
        int i = id++;
        this.oracleMap.put(i, data);
        return i;
    }

    public Map<String, String> getData(int id) {
        return this.oracleMap.get(id);
    }

    public void clearData(int id) {
        this.oracleMap.remove(id);
    }

    public void reset() {
        oracleMap = new HashMap<>();
        id = 0;
    }

    public void addListener(OracleListener listener) {
        this.listeners.add(listener);
    }

    public void removeListener(OracleListener listener) {
        this.listeners.remove(listener);
    }

    public void oracleInvoked(int id) {
        for (OracleListener listener : this.listeners) {
            listener.oracleInvoked(id);
        }
    }
}
