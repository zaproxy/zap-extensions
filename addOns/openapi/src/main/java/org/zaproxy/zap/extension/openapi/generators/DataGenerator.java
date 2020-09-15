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

import io.swagger.v3.oas.models.media.ArraySchema;
import io.swagger.v3.oas.models.media.BooleanSchema;
import io.swagger.v3.oas.models.media.DateSchema;
import io.swagger.v3.oas.models.media.DateTimeSchema;
import io.swagger.v3.oas.models.media.FileSchema;
import io.swagger.v3.oas.models.media.IntegerSchema;
import io.swagger.v3.oas.models.media.MapSchema;
import io.swagger.v3.oas.models.media.NumberSchema;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.media.StringSchema;
import io.swagger.v3.oas.models.parameters.Parameter;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class DataGenerator {

    private Generators generators;

    public DataGenerator(Generators generators) {
        this.generators = generators;
    }

    @SuppressWarnings("serial")
    private static final Map<String, String> TYPES =
            Collections.unmodifiableMap(
                    new HashMap<String, String>() {
                        {
                            put("integer", "10");
                            put("number", "1.2");
                            put("string", "\"John Doe\"");
                            put("boolean", "true");
                        }
                    });

    public boolean isSupported(Schema<?> schema) {
        return schema instanceof ArraySchema
                || schema instanceof BooleanSchema
                || schema instanceof FileSchema
                || schema instanceof IntegerSchema
                || schema instanceof MapSchema
                || schema instanceof NumberSchema
                || schema instanceof StringSchema;
    }

    public String generate(String name, Parameter parameter) {
        String defaultValue = generateDefaultValue(parameter);
        return generateParam(name, defaultValue, parameter);
    }

    private static String generateDefaultValue(Parameter parameter) {
        String value = getDefaultValue(parameter.getSchema());
        if (value != null) {
            return value;
        }
        if (parameter.getExample() != null) {
            return parameter.getExample().toString();
        }
        return "";
    }

    private static String getDefaultValue(Schema<?> schema) {
        if (schema.getDefault() != null) {
            String strValue = schema.getDefault().toString();
            if (!strValue.isEmpty()) {
                return strValue;
            }
        }
        if (schema instanceof StringSchema) {
            List<String> enumValues = ((StringSchema) schema).getEnum();
            if (enumValues != null && !enumValues.isEmpty()) {
                return enumValues.get(0);
            }
        }
        return null;
    }

    private String generateParam(String name, String example, Parameter parameter) {

        if (example != null && !example.isEmpty()) {
            return example;
        }
        if (isArray(parameter.getSchema().getType())) {
            return generateArrayValue(name, parameter);
        }

        if (parameter.getSchema() instanceof ArraySchema) {
            Schema<?> items = ((ArraySchema) (parameter.getSchema())).getItems();
            if (items != null) {
                return generateValue(name, items, isPath(parameter.getIn()));
            }
        }

        return getExampleValue(
                isPath(parameter.getIn()), parameter.getSchema().getType(), parameter.getName());
    }

    private String generateArrayValue(String name, Parameter parameter) {
        boolean isPath = isPath(parameter.getIn());
        if (!(parameter.getSchema() instanceof ArraySchema
                && ((ArraySchema) parameter.getSchema()).getItems() instanceof ArraySchema)) {
            return generateValue(name, ((ArraySchema) parameter.getSchema()).getItems(), isPath);
        }
        return generators
                .getArrayGenerator()
                .generate(
                        name,
                        ((ArraySchema) ((ArraySchema) parameter.getSchema()).getItems()),
                        "",
                        isPath);
    }

    public String generateBodyValue(String name, Schema<?> property) {
        if (isArray(property)) {
            return generators
                    .getArrayGenerator()
                    .generate(name, (ArraySchema) property, "csv", false);
        }
        if (isMap(property)) {
            return generators.getMapGenerator().generate(TYPES, property);
        }
        return generateValue(name, property, false);
    }

    public String generateValue(String name, Schema<?> schema, boolean isPath) {
        String value = getDefaultValue(schema);

        if (value == null || value.isEmpty()) {
            if (schema.getExample() != null) {
                value = schema.getExample().toString();
            } else if (isDateTime(schema)) {
                value = "1970-01-01T00:00:00.001Z";
            } else if (isDate(schema)) {
                value = "1970-01-01";
            } else {
                value = "";
            }
        }

        value = generators.getValueGenerator().getValue(name, schema.getType(), value);

        if (value.isEmpty()) {
            value = getExampleValue(isPath, schema.getType(), name);
        } else {
            if (!isPath && "string".equalsIgnoreCase(schema.getType())) {
                value = "\"" + value + "\"";
            }
        }
        if (value == null || value.isEmpty()) {
            value = generators.getBodyGenerator().generate(schema);
        }
        return value;
    }

    private String getExampleValue(boolean isPath, String type, String name) {
        if (isPath) {
            return generateExampleValueForPath(type, name);
        }
        return generateSimpleExampleValue(type);
    }

    public String generateExampleValueForPath(String type, String name) {
        String value;
        if ("string".equals(type)) {
            if (name != null) {
                value = name;
            } else {
                value = "Test";
            }
        } else {
            value = generateSimpleExampleValue(type);
        }
        return generators.getValueGenerator().getValue(name, type, value);
    }

    private String generateSimpleExampleValue(String type) {
        return TYPES.get(type);
    }

    public boolean isPath(String type) {
        return type.equals("query") || type.equals("path");
    }

    public boolean isArray(String type) {
        return "array".equals(type);
    }

    private static boolean isArray(Schema<?> schema) {
        return schema instanceof ArraySchema;
    }

    public boolean isDateTime(Schema<?> schema) {
        return schema instanceof DateTimeSchema;
    }

    public boolean isDate(Schema<?> schema) {
        return schema instanceof DateSchema;
    }

    private static boolean isMap(Schema<?> schema) {
        return schema instanceof MapSchema;
    }

    public Generators getGenerators() {
        return generators;
    }
}
