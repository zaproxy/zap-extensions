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

public class ArrayGenerator {

    private DataGenerator dataGenerator;

    /**
     * csv - comma separated values foo,bar. ssv - space separated values foo bar. tsv - tab
     * separated values foo\tbar. pipes - pipe separated values foo|bar. multi - corresponds to
     * multiple parameter instances instead of multiple values for a single instance
     * foo=bar&foo=baz. This is valid only for parameters in "query" or "formData".
     */
    private static final String ARRAY_BEGIN = "[";

    private static final String ARRAY_END = "]";

    public ArrayGenerator(DataGenerator dataGenerator) {
        this.dataGenerator = dataGenerator;
    }

    public String generate(
            String name, ArraySchema property, String collectionType, boolean isPath) {

        if (property == null) {
            return "";
        }
        if (collectionType.isEmpty()) {
            collectionType = "csv";
        }
        String valueType = property.getItems().getType();
        if (dataGenerator.isArray(valueType)) {
            if (property.getItems() instanceof ArraySchema) {
                return generate(name, (ArraySchema) property.getItems(), collectionType, isPath);
            } else {
                return "";
            }
        }
        String value = dataGenerator.generateValue(name, property.getItems(), isPath);
        return ARRAY_BEGIN + value + ARRAY_END;
    }
}
