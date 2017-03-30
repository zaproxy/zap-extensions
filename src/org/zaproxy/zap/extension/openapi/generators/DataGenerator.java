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
 *   http://www.apache.org/licenses/LICENSE-2.0 
 *   
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS, 
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
 * See the License for the specific language governing permissions and 
 * limitations under the License. 
 */
package org.zaproxy.zap.extension.openapi.generators;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import io.swagger.models.parameters.AbstractSerializableParameter;
import io.swagger.models.properties.ArrayProperty;
import io.swagger.models.properties.DateProperty;
import io.swagger.models.properties.DateTimeProperty;
import io.swagger.models.properties.Property;
import io.swagger.models.properties.RefProperty;
import io.swagger.models.properties.StringProperty;

public class DataGenerator {

    private Generators generators;
    
    public DataGenerator (Generators generators) {
        this.generators = generators;
    }

    @SuppressWarnings("serial")
    private static final Map<String, String> TYPES = Collections.unmodifiableMap(new HashMap<String, String>() {
        {
            put("integer", "10");
            put("number", "1.2");
            put("string", "\"John Doe\"");
            put("boolean", "true");
            put("array", "");
            put("file", "\u0800");
            put("ref", "ref");
        }
    });

    public boolean isSupported(String type) {
        return TYPES.get(type) != null;
    }

    public String generate(AbstractSerializableParameter<?> parameter) {
        String defaultValue = generateDefaultValue(parameter.getEnum(), parameter.getDefaultValue());
        return generateParam(defaultValue, parameter);
    }

    private static String generateDefaultValue(List<String> anEnum, String defaultValue) {
        if (defaultValue != null && !defaultValue.isEmpty()) {
            return defaultValue;
        }
        if (anEnum != null && !anEnum.isEmpty()) {
            return anEnum.get(0);
        }
        return "";
    }

    private String generateParam(String example, AbstractSerializableParameter<?> parameter) {

        if (example != null && !example.isEmpty()) {
            return example;
        }
        if (isArray(parameter.getType())) {
            return generateArrayValue(parameter);
        }

        if (parameter.getItems() != null) {
            return generateValue(parameter.getItems(), isPath(parameter.getIn()));
        }

        return getExampleValue(isPath(parameter.getIn()), parameter.getType(), parameter.getName());
    }

    private String generateArrayValue(AbstractSerializableParameter<?> parameter) {
        boolean isPath = isPath(parameter.getIn());
        if (!(parameter.getItems() instanceof ArrayProperty)) {
            return generateValue(parameter.getItems(), isPath);
        }
        return generators.getArrayGenerator().generate((ArrayProperty) parameter.getItems(), parameter.getCollectionFormat(), isPath);
    }

    public String generateBodyValue(Property property) {
        if (isArray(property.getType())) {
            return generators.getArrayGenerator().generate((ArrayProperty) property, "csv", false);
        }
        return generateValue(property, false);
    }

    public String generateValue(Property items, boolean isPath) {

        String value = "";
        if (isEnumValue(items)) {
            value = getEnumValue(items);
        }
        if (isDateTime(items)) {
            value = "1970-01-01T00:00:00.001Z";
        }
        if (isDate(items)) {
            value = "1970-01-01";
        }

        if (value.isEmpty()) {
            if ("ref".equals(items.getType())) {
                if (items instanceof RefProperty) {
                    RefProperty rp = (RefProperty) items;
                    // You'd hope there was a cleaner way to do this, but I havnt found it yet :/
                    if (rp.get$ref().startsWith("#/definitions/")) {
                        String defn = rp.get$ref().substring(14);
                        return this.generators.getBodyGenerator().generate(defn, false);
                    }
                }
            }
            value = getExampleValue(isPath, items.getType(), items.getName());

        } else {
            if (!isPath) {
                value = "\"" + value + "\"";
            }
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
        if ("string".equals(type)) {
            if (name != null) {
                return name;
            }
            return "Test";
        }
        return generateSimpleExampleValue(type);
    }

    public String generateSimpleExampleValue(String type) {
        return TYPES.get(type);
    }

    public boolean isEnumValue(Property items) {
        if (items instanceof StringProperty) {
            if (((StringProperty) items).getEnum() != null) {
                return true;
            }
        }
        return false;
    }

    public String getEnumValue(Property items) {
        String value = "";
        if (isEnumValue(items)) {
            value = ((StringProperty) items).getEnum().get(0);
        }
        return value;
    }

    public boolean isPath(String type) {
        return type.equals("query") || type.equals("path");
    }

    public boolean isArray(String type) {
        return "array".equals(type);
    }

    public boolean isDateTime(Property property) {
        return property instanceof DateTimeProperty;
    }

    public boolean isDate(Property property) {
        return property instanceof DateProperty;
    }
}
