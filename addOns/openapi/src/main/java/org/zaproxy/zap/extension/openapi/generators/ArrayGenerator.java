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
import org.zaproxy.zap.extension.openapi.OpenApiSchemaTypeUtils;

public class ArrayGenerator {

    private DataGenerator dataGenerator;

    private static final String ARRAY_BEGIN = "[";

    private static final String ARRAY_END = "]";

    public ArrayGenerator(DataGenerator dataGenerator) {
        this.dataGenerator = dataGenerator;
    }

    public String generate(String name, Schema<?> property, boolean isParam) {
        if (property == null || property.getItems() == null) {
            return "";
        }
        String value =
                OpenApiSchemaTypeUtils.isArray(property.getItems())
                        ? generate(name, property.getItems(), isParam)
                        : dataGenerator.generateValue(name, property.getItems(), isParam);
        if (isParam) {
            // params are not expected to be enclosed in brackets
            // at the moment, we only support the default serialization methods
            // ref: https://swagger.io/docs/specification/v3_0/serialization/#path-parameters
            return value;
        }
        return ARRAY_BEGIN + value + ARRAY_END;
    }
}
