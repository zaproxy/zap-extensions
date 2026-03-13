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

import io.swagger.v3.oas.models.examples.Example;
import io.swagger.v3.oas.models.media.Content;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.parameters.Parameter;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import org.zaproxy.zap.extension.openapi.OpenApiSchemaTypeUtils;

public class DataGenerator {

    private Generators generators;

    public DataGenerator(Generators generators) {
        this.generators = generators;
    }

    private static final Map<String, String> TYPES =
            Map.of(
                    OpenApiSchemaTypeUtils.TYPE_INTEGER,
                    "10",
                    OpenApiSchemaTypeUtils.TYPE_NUMBER,
                    "1.2",
                    OpenApiSchemaTypeUtils.TYPE_STRING,
                    "\"John Doe\"",
                    OpenApiSchemaTypeUtils.TYPE_BOOLEAN,
                    "true");

    public boolean isSupported(Schema<?> schema) {
        String type = OpenApiSchemaTypeUtils.getType(schema);
        return OpenApiSchemaTypeUtils.isArray(schema)
                || OpenApiSchemaTypeUtils.TYPE_BOOLEAN.equals(type)
                || OpenApiSchemaTypeUtils.TYPE_INTEGER.equals(type)
                || OpenApiSchemaTypeUtils.TYPE_NUMBER.equals(type)
                || OpenApiSchemaTypeUtils.TYPE_STRING.equals(type)
                || OpenApiSchemaTypeUtils.isMap(schema);
    }

    public String generate(String name, Parameter parameter) {
        String defaultValue = generateDefaultValue(parameter);
        return generateParam(name, defaultValue, parameter);
    }

    private static String generateDefaultValue(Parameter parameter) {
        if (parameter.getSchema() == null) {
            return "";
        }
        String value = getDefaultValue(parameter.getSchema());
        if (value != null) {
            return value;
        }
        String example = extractExample(parameter);
        if (example != null) {
            return example;
        }
        return "";
    }

    private static String extractExample(Parameter parameter) {
        return Optional.ofNullable(parameter.getExamples())
                .map(Map::values)
                .map(Collection::stream)
                .map(stream -> stream.map(Example::getValue).filter(Objects::nonNull).findFirst())
                .orElse(Optional.ofNullable(parameter.getExample()))
                .map(Object::toString)
                .orElse(
                        Optional.ofNullable(parameter.getSchema().getExample())
                                .map(Object::toString)
                                .orElse(null));
    }

    private static String getDefaultValue(Schema<?> schema) {
        if (schema.getDefault() != null) {
            String strValue = schema.getDefault().toString();
            if (!strValue.isEmpty()) {
                return strValue;
            }
        }

        List<?> enumValues = schema.getEnum();
        if (enumValues != null && !enumValues.isEmpty()) {
            return String.valueOf(enumValues.get(0));
        }
        return null;
    }

    private String generateParam(String name, String example, Parameter parameter) {

        if (example != null && !example.isEmpty()) {
            return example;
        }

        Content content = parameter.getContent();
        if (content != null) {
            if (content.containsKey("application/json")) {
                return generators.getBodyGenerator().generate(content.get("application/json"));
            }
            return getExampleValue(parameter);
        }

        if (OpenApiSchemaTypeUtils.isArray(parameter.getSchema())) {
            return generators.getArrayGenerator().generate(name, parameter.getSchema(), true);
        }

        return getExampleValue(parameter);
    }

    public String generateBodyValue(String name, Schema<?> property) {
        if (OpenApiSchemaTypeUtils.isArray(property)) {
            return generators.getArrayGenerator().generate(name, property, false);
        }
        if (OpenApiSchemaTypeUtils.isMap(property)) {
            if (property.getAdditionalProperties() instanceof Schema) {
                return generators.getMapGenerator().generate(TYPES, property);
            } else if (property.getProperties() != null && !property.getProperties().isEmpty()) {
                return generators.getBodyGenerator().generate(property);
            } else {
                return "{}";
            }
        }
        return generateValue(name, property, false);
    }

    public String generateValue(String name, Schema<?> schema, boolean isPath) {
        String value = getDefaultValue(schema);

        if (value == null || value.isEmpty()) {
            if (schema.getExample() != null) {
                value = schema.getExample().toString();
            } else if (OpenApiSchemaTypeUtils.isDateTime(schema)) {
                value = "1970-01-01T00:00:00.001Z";
            } else if (OpenApiSchemaTypeUtils.isDate(schema)) {
                value = "1970-01-01";
            } else {
                value = "";
            }
        }

        String type = OpenApiSchemaTypeUtils.getType(schema);
        value = generators.getValueGenerator().getValue(name, type, value);

        if (value.isEmpty()) {
            value = getExampleValue(isPath, type, name);
        } else {
            if (!isPath && OpenApiSchemaTypeUtils.TYPE_STRING.equalsIgnoreCase(type)) {
                value = "\"" + value + "\"";
            }
        }
        if (value == null || value.isEmpty()) {
            value = generators.getBodyGenerator().generate(schema);
        }
        return value;
    }

    private String getExampleValue(Parameter parameter) {
        String in = parameter.getIn();
        String type = OpenApiSchemaTypeUtils.getType(parameter.getSchema());
        if ("cookie".equals(in) && OpenApiSchemaTypeUtils.TYPE_STRING.equals(type)) {
            return "JohnDoe";
        }
        return getExampleValue(isPath(in), type, parameter.getName());
    }

    private String getExampleValue(boolean isPath, String type, String name) {
        if (isPath) {
            return generateExampleValueForPath(type, name);
        }
        return generateSimpleExampleValue(type);
    }

    public String generateExampleValueForPath(String type, String name) {
        String value;
        if (OpenApiSchemaTypeUtils.TYPE_STRING.equals(type)) {
            value = Objects.requireNonNullElse(name, "Test");
        } else {
            value = generateSimpleExampleValue(type);
        }
        return generators.getValueGenerator().getValue(name, type, value);
    }

    private String generateSimpleExampleValue(String type) {
        return type != null ? TYPES.get(type) : "";
    }

    public boolean isPath(String type) {
        return "query".equals(type) || "path".equals(type);
    }

    public Generators getGenerators() {
        return generators;
    }
}
