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
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import java.util.List;
import org.zaproxy.addon.postman.deserializers.ListDeserializer;
import org.zaproxy.addon.postman.deserializers.ObjectDeserializer;

/**
 * Represents an item in the Postman format which is the basic building block of a collection.
 *
 * @see https://learning.postman.com/collection-format/reference/item/
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class Item extends AbstractItem {

    @JsonDeserialize(using = ObjectDeserializer.class)
    private Request request;

    @JsonDeserialize(using = ObjectDeserializer.class)
    private String name = "Unnamed Item";

    @JsonDeserialize(using = ListDeserializer.class)
    private List<KeyValueData> variable;

    public Item() {}

    public Item(Request request) {
        this.request = request;
    }

    public Request getRequest() {
        return request;
    }

    public void setRequest(Request request) {
        this.request = request;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public List<KeyValueData> getVariable() {
        return variable;
    }

    public void setVariable(List<KeyValueData> variable) {
        this.variable = variable;
    }
}
