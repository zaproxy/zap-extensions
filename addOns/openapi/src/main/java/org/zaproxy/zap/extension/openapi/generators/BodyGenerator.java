/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2017 The ZAP Development Team
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
package org.zaproxy.zap.extension.openapi.generators;

import io.swagger.models.properties.Property;
import io.swagger.models.properties.RefProperty;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.log4j.Logger;

public class BodyGenerator {

    private Generators generators;
    private ModelGenerator modelGenerator;
    private DataGenerator dataGenerator;
    private static final Logger LOG = Logger.getLogger(BodyGenerator.class);

    public BodyGenerator(Generators generators) {
        this.generators = generators;
        this.modelGenerator = generators.getModelGenerator();
        this.dataGenerator = generators.getDataGenerator();
    }

    private enum Element {
        OBJECT_BEGIN,
        OBJECT_END,
        ARRAY_BEGIN,
        ARRAY_END,
        PROPERTY_CONTAINER,
        INNER_SEPARATOR,
        OUTER_SEPARATOR
    }

    @SuppressWarnings("serial")
    private static final Map<Element, String> SYNTAX =
            Collections.unmodifiableMap(
                    new HashMap<Element, String>() {

                        {
                            put(Element.OBJECT_BEGIN, "{");
                            put(Element.OBJECT_END, "}");
                            put(Element.ARRAY_BEGIN, "[");
                            put(Element.ARRAY_END, "]");
                            put(Element.PROPERTY_CONTAINER, "\"");
                            put(Element.INNER_SEPARATOR, ":");
                            put(Element.OUTER_SEPARATOR, ",");
                        }
                    });

    public String generate(String name, boolean isArray, List<String> refs) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Generate body for object " + name);
        }
        String jsonStr = generateJsonObjectString(name, refs);
        if (isArray) {
            jsonStr = createJsonArrayWith(jsonStr);
        }
        return jsonStr;
    }

    public String generate(Property property, boolean isArray) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Generate body for primitive type " + property.getType());
        }
        String jsonStr = generateJsonPrimitiveValue(property);
        if (isArray) {
            jsonStr = createJsonArrayWith(jsonStr);
        }
        return jsonStr;
    }

    private static String createJsonArrayWith(String jsonStr) {
        return SYNTAX.get(Element.ARRAY_BEGIN)
                + jsonStr
                + SYNTAX.get(Element.OUTER_SEPARATOR)
                + jsonStr
                + SYNTAX.get(Element.ARRAY_END);
    }

    private String generateJsonPrimitiveValue(Property property) {
        return dataGenerator.generateBodyValue("", property, new ArrayList<>());
    }

    private String generateJsonObjectString(String name, List<String> refs) {
        StringBuilder json = new StringBuilder();
        json.append(SYNTAX.get(Element.OBJECT_BEGIN));
        boolean isFirst = true;
        Map<String, Property> map = modelGenerator.getProperty(name);
        if (map != null) {
            for (Map.Entry<String, Property> property : map.entrySet()) {
                if (isFirst) {
                    isFirst = false;
                } else {
                    json.append(SYNTAX.get(Element.OUTER_SEPARATOR));
                }
                json.append(SYNTAX.get(Element.PROPERTY_CONTAINER));
                json.append(property.getKey());
                json.append(SYNTAX.get(Element.PROPERTY_CONTAINER));
                json.append(SYNTAX.get(Element.INNER_SEPARATOR));
                String value;
                if (dataGenerator.isSupported(property.getValue().getType())) {
                    value =
                            dataGenerator.generateBodyValue(
                                    property.getKey(), property.getValue(), refs);
                } else {
                    if (property.getValue() instanceof RefProperty) {
                        value =
                                generate(
                                        ((RefProperty) property.getValue()).getSimpleRef(),
                                        false,
                                        refs);
                    } else {
                        value =
                                generators
                                        .getValueGenerator()
                                        .getValue(
                                                property.getKey(),
                                                property.getValue().getType(),
                                                generate(
                                                        property.getValue().getName(),
                                                        false,
                                                        refs));
                    }
                }

                json.append(value);
            }
        }
        json.append(SYNTAX.get(Element.OBJECT_END));
        return json.toString();
    }
}
