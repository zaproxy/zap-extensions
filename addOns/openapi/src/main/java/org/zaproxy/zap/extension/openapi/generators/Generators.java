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

import io.swagger.v3.oas.models.media.Schema;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.zaproxy.addon.commonlib.ValueProvider;

public class Generators {

    // OpenAPI schema type constants
    static final String TYPE_ARRAY = "array";
    static final String TYPE_BOOLEAN = "boolean";
    static final String TYPE_INTEGER = "integer";
    static final String TYPE_NUMBER = "number";
    static final String TYPE_OBJECT = "object";
    static final String TYPE_STRING = "string";

    // OpenAPI schema format constants
    static final String FORMAT_BINARY = "binary";
    static final String FORMAT_DATE = "date";
    static final String FORMAT_DATE_TIME = "date-time";

    private ValueGenerator valueGenerator;
    private ArrayGenerator arrayGenerator;
    private MapGenerator mapGenerator;

    private BodyGenerator bodyGenerator;
    private DataGenerator dataGenerator;
    private PathGenerator pathGenerator;
    private List<String> errorMessages = new ArrayList<>();

    public Generators(ValueProvider valueProvider) {
        this.valueGenerator = new ValueGenerator(valueProvider);
        this.dataGenerator = new DataGenerator(this);
        this.bodyGenerator = new BodyGenerator(this);
        this.arrayGenerator = new ArrayGenerator(this.dataGenerator);
        this.pathGenerator = new PathGenerator(this.dataGenerator);
        this.mapGenerator = new MapGenerator(this.dataGenerator);
    }

    public ArrayGenerator getArrayGenerator() {
        return arrayGenerator;
    }

    public BodyGenerator getBodyGenerator() {
        return bodyGenerator;
    }

    public DataGenerator getDataGenerator() {
        return dataGenerator;
    }

    public PathGenerator getPathGenerator() {
        return pathGenerator;
    }

    public void addErrorMessage(String error) {
        this.errorMessages.add(error);
    }

    public List<String> getErrorMessages() {
        return this.errorMessages;
    }

    public ValueGenerator getValueGenerator() {
        return this.valueGenerator;
    }

    public MapGenerator getMapGenerator() {
        return mapGenerator;
    }

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

    static boolean isArray(Schema<?> schema) {
        return TYPE_ARRAY.equals(getType(schema));
    }

    static boolean isBinary(Schema<?> schema) {
        return TYPE_STRING.equals(getType(schema)) && FORMAT_BINARY.equals(schema.getFormat());
    }

    static boolean isComposed(Schema<?> schema) {
        return schema.getOneOf() != null || schema.getAnyOf() != null;
    }

    static boolean isDate(Schema<?> schema) {
        return TYPE_STRING.equals(getType(schema)) && FORMAT_DATE.equals(schema.getFormat());
    }

    static boolean isDateTime(Schema<?> schema) {
        return TYPE_STRING.equals(getType(schema)) && FORMAT_DATE_TIME.equals(schema.getFormat());
    }

    static boolean isMap(Schema<?> schema) {
        return TYPE_OBJECT.equals(getType(schema)) && schema.getAdditionalProperties() != null;
    }
}
