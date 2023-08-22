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
import com.fasterxml.jackson.databind.BeanProperty;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.cfg.CoercionAction;
import com.fasterxml.jackson.databind.cfg.CoercionInputShape;
import com.fasterxml.jackson.databind.deser.ContextualDeserializer;
import com.fasterxml.jackson.databind.type.LogicalType;
import java.io.IOException;

/**
 * A custom JSON deserializer to ignore properties of an object when its signature doesn't match,
 * rather than throwing an exception.
 */
public class ObjectDeserializer extends JsonDeserializer<Object> implements ContextualDeserializer {

    private final Class<?> targetClass;
    private final ObjectMapper mapper;

    public ObjectDeserializer() {
        this(null);
    }

    public ObjectDeserializer(Class<? extends Object> targetClass) {
        this.targetClass = targetClass;
        this.mapper = new ObjectMapper();
        configureMapper();
    }

    private void configureMapper() {
        mapper.coercionConfigFor(LogicalType.Textual)
                .setCoercion(CoercionInputShape.Boolean, CoercionAction.Fail)
                .setCoercion(CoercionInputShape.String, CoercionAction.Fail)
                .setCoercion(CoercionInputShape.Integer, CoercionAction.Fail);
    }

    @Override
    public JsonDeserializer<Object> createContextual(
            final DeserializationContext deserializationContext, final BeanProperty beanProperty)
            throws JsonMappingException {
        // Determine target type
        final Class<?> targetClass;
        {
            final JavaType type;
            if (beanProperty != null) {
                type = beanProperty.getType();
            } else {
                type = deserializationContext.getContextualType();
            }
            targetClass = type.getRawClass();
        }

        return new ObjectDeserializer(targetClass);
    }

    @Override
    public Object deserialize(JsonParser jsonParser, DeserializationContext ctxt)
            throws IOException {
        JsonNode node = jsonParser.getCodec().readTree(jsonParser);

        try {
            return mapper.treeToValue(node, targetClass);
        } catch (IOException e) {
            return null;
        }
    }
}
