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

import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import net.sf.json.JSONObject;
import org.zaproxy.zap.extension.httppanel.Message;

public class ClientMessage implements Message {

    public enum State {
        received,
        pending,
        resent,
        dropped,
        oraclehit
    }

    /** Fields that will always be reflected back if included in the original message */
    private static final String[] REFLECT_FIELDS = {"eventData", "originalEventTarget"};

    private long index = -1;
    private JSONObject json;
    private String clientId;
    private Date received;
    private State state = State.received;
    private boolean changed = false;
    private Map<String, Object> extraFields = new HashMap<String, Object>();

    public ClientMessage() {
        json = new JSONObject();
    }

    public ClientMessage(String clientId, JSONObject json) {
        super();
        setReceived(new Date());
        this.clientId = clientId;
        // Copy the full json structure, otherwise can be affected by 'external' changes
        this.setJson(JSONObject.fromObject(json.toString()));
    }

    public long getIndex() {
        return index;
    }

    public void setIndex(long index) {
        this.index = index;
    }

    public void setJson(JSONObject json) {
        this.json = json;
    }

    public Date getReceived() {
        return received;
    }

    public void setReceived(Date received) {
        this.received = received;
    }

    public String getFrom() {
        return this.json.optString("from", null);
    }

    public void setFrom(String from) {
        this.json.put("from", from);
    }

    public String getTo() {
        return this.json.optString("to", null);
    }

    public void setTo(String to) {
        this.json.put("to", to);
    }

    @Override
    public String getType() {
        return this.json.optString("type", null);
    }

    public void setType(String type) {
        this.json.put("type", type);
    }

    public String getData() {
        return this.json.optString("data", null);
    }

    public void setData(String data) {
        this.json.put("data", data);
    }

    public String getEndpointId() {
        return this.json.optString("endpointId", null);
    }

    public void setEndpointId(String endpointId) {
        this.json.put("endpointId", endpointId);
    }

    public Map<String, Object> toMap() {
        // TODO: can maybe just pull the values map from this.json and augment a clone of that?
        HashMap<String, Object> map = new HashMap<String, Object>();
        if (this.getTo() != null) {
            map.put("to", this.getTo());
        }
        if (this.getFrom() != null) {
            map.put("from", this.getFrom());
        }
        if (this.getType() != null) {
            map.put("type", this.getType());
        }
        if (this.getTarget() != null) {
            map.put("target", this.getTarget());
        }
        if (this.getData() != null) {
            map.put("data", this.getData());
        }
        if (this.getMessageId() != null) {
            map.put("messageId", this.getMessageId());
        }
        if (this.getEndpointId() != null) {
            map.put("endpointId", this.getEndpointId());
        }
        // Reflect these fields if they are present
        for (String field : REFLECT_FIELDS) {
            Object eventData = this.json.get(field);
            if (eventData != null) {
                map.put(field, eventData);
            }
        }
        // Include anything else we've been told to add
        for (Entry<String, Object> entry : this.extraFields.entrySet()) {
            map.put(entry.getKey(), entry.getValue());
        }
        if (changed) {
            map.put("changed", true);
        }
        return map;
    }

    public String getTarget() {
        return this.json.optString("target", null);
    }

    public void setTarget(String target) {
        this.json.put("target", target);
    }

    public String getMessageId() {
        return this.json.optString("messageId", null);
    }

    public void setMessageId(String messageId) {
        this.json.put("messageId", messageId);
    }

    public JSONObject getJson() {
        return json;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    @Override
    public boolean isInScope() {
        return false;
    }

    @Override
    public boolean isForceIntercept() {
        return false;
    }

    public boolean isChanged() {
        return changed;
    }

    public void setChanged(boolean changed) {
        this.changed = changed;
    }

    public State getState() {
        return state;
    }

    public void setState(State state) {
        this.state = state;
    }

    public void set(String key, Object value) {
        if (value == null) {
            this.extraFields.remove(key);
            this.json.remove(key);
        } else {
            this.extraFields.put(key, value);
            this.json.put(key, value);
        }
    }

    public String getString(String key) {
        return this.json.optString(key);
    }

    public boolean getBoolean(String key) {
        if (json.containsKey(key)) {
            return this.json.getBoolean(key);
        }
        return false;
    }

    public Map<String, Object> getExtraFields() {
        return Collections.unmodifiableMap(this.extraFields);
    }
}
