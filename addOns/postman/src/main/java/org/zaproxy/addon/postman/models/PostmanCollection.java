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
import org.zaproxy.addon.postman.deserializers.ListItemDeserializer;

/**
 * Represents a collection in the Postman format.
 *
 * @see https://learning.postman.com/collection-format/reference/collection/
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class PostmanCollection {

    @JsonDeserialize(using = ListItemDeserializer.class)
    private List<AbstractItem> item;

    @JsonDeserialize(using = ListDeserializer.class)
    private List<KeyValueData> variable;

    public List<AbstractItem> getItem() {
        return item;
    }

    public void setItem(List<AbstractItem> item) {
        this.item = item;
    }

    public List<KeyValueData> getVariable() {
        return variable;
    }

    public void setVariable(List<KeyValueData> variable) {
        this.variable = variable;
    }
}
