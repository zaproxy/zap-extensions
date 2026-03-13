/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.zap.extension.openapi;

import io.swagger.v3.core.util.SchemaTypeUtils;
import io.swagger.v3.oas.models.media.Schema;
import java.util.Set;

public class OpenApiSchemaTypeUtils {

    // OpenAPI schema type constants
    public static final String TYPE_BOOLEAN = "boolean";
    public static final String TYPE_INTEGER = "integer";
    public static final String TYPE_NUMBER = "number";
    public static final String TYPE_STRING = "string";

    // OpenAPI schema format constants
    static final String FORMAT_BINARY = "binary";
    static final String FORMAT_DATE = "date";
    static final String FORMAT_DATE_TIME = "date-time";
    private static final Set<String> TYPE_PRIMITIVES =
            Set.of(TYPE_BOOLEAN, TYPE_INTEGER, TYPE_NUMBER, TYPE_STRING);

    public static String getType(Schema<?> schema) {
        if (schema == null) {
            return null;
        }
        String type = schema.getType();
        if (type == null) {
            Set<String> types = schema.getTypes();
            if (types != null && !types.isEmpty()) {
                type = types.iterator().next();
            }
        }
        return type;
    }

    public static boolean isPrimitive(Schema<?> schema) {
        String type = getType(schema);
        return type != null && TYPE_PRIMITIVES.contains(getType(schema));
    }

    public static boolean isArray(Schema<?> schema) {
        return SchemaTypeUtils.isArraySchema(schema) && schema.getItems() != null;
    }

    public static boolean isBinary(Schema<?> schema) {
        return SchemaTypeUtils.isStringSchema(schema) && FORMAT_BINARY.equals(schema.getFormat());
    }

    public static boolean isComposed(Schema<?> schema) {
        return schema.getOneOf() != null || schema.getAnyOf() != null;
    }

    public static boolean isDate(Schema<?> schema) {
        return SchemaTypeUtils.isStringSchema(schema) && FORMAT_DATE.equals(schema.getFormat());
    }

    public static boolean isDateTime(Schema<?> schema) {
        return SchemaTypeUtils.isStringSchema(schema)
                && FORMAT_DATE_TIME.equals(schema.getFormat());
    }

    public static boolean isMap(Schema<?> schema) {
        return isObject(schema) && schema.getAdditionalProperties() != null;
    }

    public static boolean isObject(Schema<?> schema) {
        return SchemaTypeUtils.isObjectSchema(schema);
    }
}
