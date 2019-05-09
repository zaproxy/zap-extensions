/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2015 The ZAP Development Team
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
package org.zaproxy.zap.extension.fuzz.httpfuzzer;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.parosproxy.paros.network.HttpMessage;

public class HttpFuzzResult {

    private final long taskId;
    private final String type;

    private final Map<String, Object> customStates;
    private final HttpMessage message;
    private final List<Object> payloads;

    public HttpFuzzResult(long taskId, String type, HttpMessage message) {
        this(taskId, type, message, Collections.emptyList());
    }

    public HttpFuzzResult(long taskId, String type, HttpMessage message, List<Object> payloads) {
        this.taskId = taskId;
        this.type = type;
        this.customStates = new HashMap<>();
        this.message = message;
        this.payloads = payloads;
    }

    public long getTaskId() {
        return taskId;
    }

    public String getType() {
        return type;
    }

    public List<Object> getPayloads() {
        return payloads;
    }

    public HttpMessage getHttpMessage() {
        return message;
    }

    public void addCustomState(String key, Object state) {
        if (key == null || key.isEmpty() || state == null) {
            return;
        }
        this.customStates.put(key, state);
    }

    public void removeCustomState(String key) {
        if (key == null || key.isEmpty()) {
            return;
        }
        this.customStates.remove(key);
    }

    public Map<String, Object> getCustomStates() {
        return Collections.unmodifiableMap(customStates);
    }
}
