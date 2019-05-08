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

import org.apache.log4j.Logger;

import io.swagger.models.parameters.AbstractSerializableParameter;
import io.swagger.models.properties.ArrayProperty;
import io.swagger.models.properties.DateProperty;
import io.swagger.models.properties.DateTimeProperty;
import io.swagger.models.properties.Property;
import io.swagger.models.properties.RefProperty;
import io.swagger.models.properties.StringProperty;

public class DataGenerator {

    private Generators generators;
    private static final Logger LOG = Logger.getLogger(DataGenerator.class);

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

    public String generate(String name, AbstractSerializableParameter<?> parameter, List<String> refs) {
        String defaultValue = generateDefaultValue(parameter.getEnum(), parameter.getDefaultValue());
        return generateParam(name, defaultValue, parameter, refs);
    }

    private static String generateDefaultValue(List<String> anEnum, Object defaultValue) {
        if (defaultValue != null) {
            String strValue = defaultValue.toString();
            if (!strValue.isEmpty()) {
                return strValue;
            }
        }
        if (anEnum != null && !anEnum.isEmpty()) {
            return anEnum.get(0);
        }
        return "";
    }

    private String generateParam(String name, String example, AbstractSerializableParameter<?> parameter, List<String> refs) {

        if (example != null && !example.isEmpty()) {
            return example;
        }
        if (isArray(parameter.getType())) {
            return generateArrayValue(name, parameter, refs);
        }

        if (parameter.getItems() != null) {
            return generateValue(name, parameter.getItems(), isPath(parameter.getIn()), refs);
        }

        return getExampleValue(isPath(parameter.getIn()), parameter.getType(), parameter.getName());
    }

    private String generateArrayValue(String name, AbstractSerializableParameter<?> parameter, List<String> refs) {
        boolean isPath = isPath(parameter.getIn());
        if (!(parameter.getItems() instanceof ArrayProperty)) {
            return generateValue(name, parameter.getItems(), isPath, refs);
        }
        return generators.getArrayGenerator().generate(name, (ArrayProperty) parameter.getItems(), parameter.getCollectionFormat(), isPath, refs);
    }

    public String generateBodyValue(String name, Property property, List<String> refs) {
        if (isArray(property.getType())) {
            return generators.getArrayGenerator().generate(name, (ArrayProperty) property, "csv", false, refs);
        }
        return generateValue(name, property, false, refs);
    }

    public String generateValue(String name, Property items, boolean isPath, List<String> refs) {
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
        
        value = generators.getValueGenerator().getValue(name, items.getType(), value);

        if (value.isEmpty()) {
            if ("ref".equals(items.getType())) {
                if (items instanceof RefProperty) {
                    RefProperty rp = (RefProperty) items;
                    // You'd hope there was a cleaner way to do this, but I havnt found it yet :/
                    if (rp.get$ref().startsWith("#/definitions/")) {
                        String defn = rp.get$ref().substring(14);
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("Dereferencing definition: " + defn);
                        }
                        if(refs.contains(defn)) {
                            // Likely to be a loop
                            StringBuilder sb = new StringBuilder();
                            sb.append("Apparent loop in the OpenAPI definition: ");
                            for (String ref : refs) {
                                sb.append(" / ");
                                sb.append(ref);
                            }
                            this.generators.addErrorMessage(sb.toString());
                            return "";
                        } else {
                            refs.add(defn);
                            return this.generators.getBodyGenerator().generate(defn, false, refs);
                        }
                    }
                }
            }
            value = getExampleValue(isPath, items.getType(), name);

        } else {
            if (!isPath && "string".equalsIgnoreCase(items.getType())) {
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
