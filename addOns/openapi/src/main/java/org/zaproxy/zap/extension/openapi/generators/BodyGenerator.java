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

import com.fasterxml.jackson.core.JsonProcessingException;
import io.swagger.v3.core.util.Json;
import io.swagger.v3.oas.models.media.ArraySchema;
import io.swagger.v3.oas.models.media.ComposedSchema;
import io.swagger.v3.oas.models.media.Schema;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import org.apache.log4j.Logger;

public class BodyGenerator {

    private Generators generators;
    private DataGenerator dataGenerator;
    private static final Logger LOG = Logger.getLogger(BodyGenerator.class);

    public BodyGenerator(Generators generators) {
        this.generators = generators;
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

    public String generate(Schema<?> schema) {
        if (schema == null) {
            return "";
        }

        boolean isArray = schema instanceof ArraySchema;
        if (LOG.isDebugEnabled()) {
            LOG.debug("Generate body for object " + schema.getName());
        }

        if (isArray) {
            return generateFromArraySchema((ArraySchema) schema);
        }

        @SuppressWarnings("rawtypes")
        Map<String, Schema> properties = schema.getProperties();
        if (properties != null) {
            return generateFromObjectSchema(properties);
        } else if (schema.getAdditionalProperties() instanceof Schema) {
            return generate((Schema<?>) schema.getAdditionalProperties());
        }

        if (schema instanceof ComposedSchema) {
            return generateJsonPrimitiveValue(resolveComposedSchema((ComposedSchema) schema));
        }
        if (schema.getNot() != null) {
            resolveNotSchema(schema);
        }

        // primitive type, or schema without properties
        if (schema.getType() == null || schema.getType().equals("object")) {
            schema.setType("string");
        }

        return generateJsonPrimitiveValue(schema);
    }

    private String generateFromArraySchema(ArraySchema schema) {
        if (schema.getExample() instanceof String) {
            return (String) schema.getExample();
        }

        if (schema.getExample() instanceof Iterable) {
            try {
                return Json.mapper().writeValueAsString(schema.getExample());
            } catch (JsonProcessingException e) {
                LOG.warn(
                        "Failed to encode Example Object. Falling back to default example generation",
                        e);
            }
        }

        return createJsonArrayWith(generate(schema.getItems()));
    }

    @SuppressWarnings("rawtypes")
    private String generateFromObjectSchema(Map<String, Schema> properties) {
        StringBuilder json = new StringBuilder();
        boolean isFirst = true;
        json.append(SYNTAX.get(Element.OBJECT_BEGIN));
        for (Map.Entry<String, Schema> property : properties.entrySet()) {
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
            if (dataGenerator.isSupported(property.getValue())) {
                value = dataGenerator.generateBodyValue(property.getKey(), property.getValue());
            } else {

                value =
                        generators
                                .getValueGenerator()
                                .getValue(
                                        property.getKey(),
                                        property.getValue().getType(),
                                        generate(property.getValue()));
            }
            json.append(value);
        }
        json.append(SYNTAX.get(Element.OBJECT_END));
        return json.toString();
    }

    private static String createJsonArrayWith(String jsonStr) {
        return SYNTAX.get(Element.ARRAY_BEGIN)
                + jsonStr
                + SYNTAX.get(Element.OUTER_SEPARATOR)
                + jsonStr
                + SYNTAX.get(Element.ARRAY_END);
    }

    private String generateJsonPrimitiveValue(Schema<?> schema) {
        return dataGenerator.generateBodyValue("", schema);
    }

    private static Schema<?> resolveComposedSchema(ComposedSchema schema) {

        if (schema.getOneOf() != null) {
            return schema.getOneOf().get(0);
        } else if (schema.getAnyOf() != null) {
            return schema.getAnyOf().get(0);
        }
        // Should not be reached, allOf schema is resolved by the parser
        LOG.error("Unknown composed schema type: " + schema);
        return null;
    }

    private static void resolveNotSchema(Schema<?> schema) {
        if (schema.getNot().getType().equals("string")) {
            schema.setType("integer");
        } else {
            schema.setType("string");
        }
    }

    @SuppressWarnings("serial")
    private static final Map<Element, String> FORMSYNTAX =
            Collections.unmodifiableMap(
                    new HashMap<Element, String>() {
                        {
                            put(Element.INNER_SEPARATOR, "=");
                            put(Element.OUTER_SEPARATOR, "&");
                        }
                    });

    @SuppressWarnings("rawtypes")
    public String generateForm(Schema<?> schema) {
        Map<String, Schema> properties = schema.getProperties();
        if (properties != null) {
            StringBuilder formData = new StringBuilder();
            for (Map.Entry<String, Schema> property : properties.entrySet()) {
                formData.append(urlEncode(property.getKey()));
                formData.append(FORMSYNTAX.get(Element.INNER_SEPARATOR));
                formData.append(
                        urlEncode(
                                dataGenerator.generateValue(
                                        property.getKey(), property.getValue(), true)));
                formData.append(FORMSYNTAX.get(Element.OUTER_SEPARATOR));
            }
            return formData.substring(0, formData.length() - 1);
        }
        return "";
    }

    private static String urlEncode(String string) {
        try {
            return URLEncoder.encode(string, StandardCharsets.UTF_8.name());
        } catch (UnsupportedEncodingException ignore) {
            // Shouldn't happen, standard charset.
            return "";
        }
    }
}
