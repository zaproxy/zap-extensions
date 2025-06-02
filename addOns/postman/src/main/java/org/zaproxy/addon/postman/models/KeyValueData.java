/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.zaproxy.addon.postman.models;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.annotation.Nulls;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import org.zaproxy.addon.postman.deserializers.ObjectDeserializer;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonTypeInfo(use = JsonTypeInfo.Id.DEDUCTION)
public class KeyValueData extends AbstractListElement {
    public KeyValueData() {}

    public KeyValueData(String key, String value) {
        this(key, value, null);
    }

    public KeyValueData(String key, String value, String type) {
        this.key = key;
        this.value = value;
        this.type = type;
    }

    @JsonSetter(nulls = Nulls.SKIP)
    @JsonDeserialize(using = ObjectDeserializer.class)
    private String key = "";

    @JsonSetter(nulls = Nulls.SKIP)
    @JsonDeserialize(using = ObjectDeserializer.class)
    private String value = "";

    @JsonDeserialize(using = ObjectDeserializer.class)
    private boolean disabled;

    @JsonSetter(nulls = Nulls.SKIP)
    @JsonDeserialize(using = ObjectDeserializer.class)
    private String src = "";

    @JsonDeserialize(using = ObjectDeserializer.class)
    private String type;

    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public Boolean isDisabled() {
        return disabled;
    }

    public void setDisabled(Boolean disabled) {
        this.disabled = disabled;
    }

    public String getSrc() {
        return src;
    }

    public void setSrc(String src) {
        this.src = src;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }
}
