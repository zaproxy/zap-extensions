/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
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

import static org.zaproxy.zap.extension.openapi.generators.Element.Json.INNER_SEPARATOR;
import static org.zaproxy.zap.extension.openapi.generators.Element.Json.OBJECT_BEGIN;
import static org.zaproxy.zap.extension.openapi.generators.Element.Json.OBJECT_END;
import static org.zaproxy.zap.extension.openapi.generators.Element.OpenApiType.STRING;

import io.swagger.v3.oas.models.media.BooleanSchema;
import io.swagger.v3.oas.models.media.IntegerSchema;
import io.swagger.v3.oas.models.media.NumberSchema;
import io.swagger.v3.oas.models.media.ObjectSchema;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.media.StringSchema;
import java.util.Map;

public class MapGenerator {

    private BodyGenerator bodyGenerator;

    public MapGenerator(DataGenerator dataGenerator) {
        this.bodyGenerator = dataGenerator.getGenerators().getBodyGenerator();
    }

    /**
     * @param types the data types supported with their corresponding default values
     * @param property Can be {@link NumberSchema}, {@link IntegerSchema}, {@link StringSchema} and
     *     {@link BooleanSchema}. For any other schema type, i.g {@link ObjectSchema}, the {@link
     *     BodyGenerator#generate(Schema)} is invoked to start the value generation again.
     * @return a key value JSON structure where the key is default to string as per Swagger/OpenApi
     *     specification.
     */
    public String generate(Map<String, String> types, Schema<?> property) {
        Schema<?> schema = (Schema<?>) property.getAdditionalProperties();
        String type = types.get(schema.getType());
        String value = type != null ? type : bodyGenerator.generate(schema);
        String defaultKey = types.get(STRING.type());
        return OBJECT_BEGIN + defaultKey + INNER_SEPARATOR + value + OBJECT_END;
    }
}
