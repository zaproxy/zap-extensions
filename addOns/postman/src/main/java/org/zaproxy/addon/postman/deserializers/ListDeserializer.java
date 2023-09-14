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
package org.zaproxy.addon.postman.deserializers;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.zaproxy.addon.postman.models.AbstractListElement;

public class ListDeserializer extends JsonDeserializer<List<AbstractListElement>> {

    @Override
    public List<AbstractListElement> deserialize(JsonParser jsonParser, DeserializationContext ctxt)
            throws IOException {
        JsonNode itemsNode = jsonParser.getCodec().readTree(jsonParser);

        if (itemsNode.isArray()) {
            return deserializeArray(jsonParser, itemsNode);
        } else if (itemsNode.isObject()) {
            return deserializeObject(jsonParser, itemsNode);
        }

        return List.of();
    }

    private static List<AbstractListElement> deserializeArray(
            JsonParser jsonParser, JsonNode itemsNode) {
        List<AbstractListElement> items = new ArrayList<>();
        for (JsonNode itemNode : itemsNode) {
            AbstractListElement item = deserializeItem(jsonParser, itemNode);
            if (item != null) {
                items.add(item);
            }
        }
        return Collections.unmodifiableList(items);
    }

    private static List<AbstractListElement> deserializeObject(
            JsonParser jsonParser, JsonNode itemNode) {
        AbstractListElement item = deserializeItem(jsonParser, itemNode);
        return (item != null) ? List.of(item) : List.of();
    }

    private static AbstractListElement deserializeItem(JsonParser jsonParser, JsonNode itemNode) {
        try {
            return jsonParser.getCodec().treeToValue(itemNode, AbstractListElement.class);
        } catch (Exception e) {
            return null;
        }
    }
}
