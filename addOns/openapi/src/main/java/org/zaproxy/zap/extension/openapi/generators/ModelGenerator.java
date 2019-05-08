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

import io.swagger.models.Model;
import io.swagger.models.properties.Property;
import io.swagger.models.properties.RefProperty;

import java.util.HashMap;
import java.util.Map;

public class ModelGenerator {

    private Map<String, Model> definitions;

    public void setDefinitions(Map<String, Model> definitions) {
        this.definitions = definitions;
    }

    public Map<String, String> generate(String name) {
        Map<String, String> model = new HashMap<String, String>();
        for (Map.Entry<String, Model> definition : definitions.entrySet()) {
            if (definition.getKey().equals(name)) {
                for (Map.Entry<String, Property> property : definition.getValue().getProperties().entrySet()) {
                    if (property.getValue().getType().equals("ref")) {
                        model.put(property.getKey(), ((RefProperty) property.getValue()).getSimpleRef());
                    } else {
                        model.put(property.getKey(), property.getValue().getType());
                    }
                }
            }
        }
        return model;
    }

    public Map<String, Property> getProperty(String name) {
        for (Map.Entry<String, Model> definition : definitions.entrySet()) {
            if (definition.getKey().equals(name)) {

                return definition.getValue().getProperties();
            }
        }
        return new HashMap<String, Property>();
    }
}