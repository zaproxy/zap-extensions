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

import com.fasterxml.jackson.core.JsonProcessingException;
import io.swagger.v3.core.util.Json;
import io.swagger.v3.oas.models.headers.Header;
import io.swagger.v3.oas.models.media.ArraySchema;
import io.swagger.v3.oas.models.media.BinarySchema;
import io.swagger.v3.oas.models.media.ComposedSchema;
import io.swagger.v3.oas.models.media.Encoding;
import io.swagger.v3.oas.models.media.ObjectSchema;
import io.swagger.v3.oas.models.media.Schema;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import org.apache.log4j.Logger;

public class BodyGenerator {

    private Generators generators;
    private DataGenerator dataGenerator;
    private static final Logger LOG = Logger.getLogger(BodyGenerator.class);

    public BodyGenerator(Generators generators) {
        this.generators = generators;
        this.dataGenerator = generators.getDataGenerator();
    }

    private enum Element {
        OBJECT_BEGIN,
        OBJECT_END,
        ARRAY_BEGIN,
        ARRAY_END,
        PROPERTY_CONTAINER,
        INNER_SEPARATOR,
        OUTER_SEPARATOR
    }

    @SuppressWarnings("serial")
    private static final Map<Element, String> SYNTAX =
            Collections.unmodifiableMap(
                    new HashMap<Element, String>() {
                        {
                            put(Element.OBJECT_BEGIN, "{");
                            put(Element.OBJECT_END, "}");
                            put(Element.ARRAY_BEGIN, "[");
                            put(Element.ARRAY_END, "]");
                            put(Element.PROPERTY_CONTAINER, "\"");
                            put(Element.INNER_SEPARATOR, ":");
                            put(Element.OUTER_SEPARATOR, ",");
                        }
                    });

    public String generate(Schema<?> schema) {
        if (schema == null) {
            return "";
        }

        LOG.debug("Generate body for object " + schema.getName());

        if (schema instanceof ArraySchema) {
            return generateFromArraySchema((ArraySchema) schema);
        } else if (schema instanceof BinarySchema) {
            return generateFromBinarySchema((BinarySchema) schema, false);
        }

        @SuppressWarnings("rawtypes")
        Map<String, Schema> properties = schema.getProperties();
        if (properties != null) {
            return generateFromObjectSchema(properties);
        } else if (schema.getAdditionalProperties() instanceof Schema) {
            return generate((Schema<?>) schema.getAdditionalProperties());
        }

        if (schema instanceof ComposedSchema) {
            return generateJsonPrimitiveValue(resolveComposedSchema((ComposedSchema) schema));
        }
        if (schema.getNot() != null) {
            resolveNotSchema(schema);
        }

        // primitive type, or schema without properties
        if (schema.getType() == null || schema.getType().equals("object")) {
            schema.setType("string");
        }

        return generateJsonPrimitiveValue(schema);
    }

    private String generateFromArraySchema(ArraySchema schema) {
        if (schema.getExample() instanceof String) {
            return (String) schema.getExample();
        }

        if (schema.getExample() instanceof Iterable) {
            try {
                return Json.mapper().writeValueAsString(schema.getExample());
            } catch (JsonProcessingException e) {
                LOG.warn(
                        "Failed to encode Example Object. Falling back to default example generation",
                        e);
            }
        }

        return createJsonArrayWith(generate(schema.getItems()));
    }

    private String generateFromBinarySchema(BinarySchema schema, Boolean isImage) {
        if (isImage) {

            byte[] data =
                    new byte[] {
                        -119, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 73, 72, 68, 82, 0, 0, 0, 32,
                        0, 0, 0, 32, 8, 6, 0, 0, 0, 115, 122, 122, -12, 0, 0, 0, 6, 98, 75, 71, 68,
                        0, -1, 0, -1, 0, -1, -96, -67, -89, -109, 0, 0, 0, 9, 112, 72, 89, 115, 0,
                        0, 26, -101, 0, 0, 26, -101, 1, -35, 110, 70, -45, 0, 0, 0, 7, 116, 73, 77,
                        69, 7, -31, 11, 10, 12, 52, 15, 43, 46, -92, -16, 0, 0, 7, 26, 73, 68, 65,
                        84, 88, -61, -67, -105, 125, 108, 85, 103, 29, -57, 63, -65, -25, -100, 115,
                        111, 11, 125, 65, -41, 73, 19, 16, -91, -68, -116, -51, -59, 50, -119, 13,
                        -104, -74, -38, -126, 82, 108, 86, 105, -103, 22, -8, -125, -53, 31, -122,
                        -111, 8, -63, 116, 13, 76, -88, 116, 53, -120, 34, 48, -94, 48, -93, -112,
                        44, 116, -116, 93, 66, 87, 70, 52, 19, 121, 91, 99, -109, 21, 21, 92, 33,
                        -111, 53, 99, 1, 49, 113, 115, -99, 115, 80, -54, -6, 114, -17, 57, -49,
                        -49, 63, -50, -19, 11, -48, -106, -78, 63, 124, 110, -98, -100, -109, 115,
                        -97, 115, -98, -17, -17, -19, -5, -3, 61, -16, 96, 99, 46, 112, 20, 120, 23,
                        -8, 10, -1, -57, -79, 2, -24, 0, 116, -11, -22, -43, -70, 113, -29, 70, 5,
                        122, 70, 93, 29, -117, -113, -5, -61, -18, 24, -1, -91, 1, -49, 2, -101, 50,
                        50, 50, -46, -22, -22, -22, -88, -83, -83, -59, 113, 28, 0, -50, -98, 61,
                        -101, -2, -42, -65, -109, -67, -26, -37, 13, 17, -4, -124, 42, -4, 7, -12,
                        29, 85, -38, 20, -5, 26, 112, 126, 60, 0, 100, -124, 103, -113, 2, -11, 64,
                        -11, -36, -71, 115, -87, -81, -81, 103, -23, -46, -91, -9, 44, -22, -18,
                        -18, 38, 43, 43, -117, 104, 73, 13, 78, 94, 17, -118, -94, 26, 78, -117, 37,
                        80, 123, 67, 85, -97, -45, -58, 21, -65, 34, 22, -121, -58, 21, 35, 2, 48,
                        -61, -18, -105, 1, 23, -127, -73, 87, -82, 92, 89, -35, -47, -47, 65, 123,
                        123, -5, -120, -101, 3, 100, 102, 102, -46, -36, -36, 76, 127, -53, -13,
                        -72, 126, 15, 17, 49, 68, -116, 75, -60, 113, -119, 24, -113, -88, -15, 62,
                        -29, 26, -25, -105, 78, -20, -56, 13, -48, -7, -93, 121, -64, 0, -27, -64,
                        -19, 104, 52, -6, 106, 67, 67, 67, 126, 95, 95, 31, -121, 15, 31, 102, -50,
                        -100, 57, -9, 117, 95, 85, 85, 21, -107, -107, 85, 124, -14, -5, 45, 120,
                        -47, 116, 92, 35, -72, -58, -32, 58, 6, -49, 113, -120, 24, 15, -49, -15,
                        38, -71, -30, -100, 35, 22, -81, 31, 41, 63, 4, -8, -25, -106, 45, 91, -90,
                        109, -37, -74, -19, 83, 103, 104, 102, -58, 68, -28, -15, -89, -104, 48,
                        -81, 26, 107, 45, 86, 21, 85, -80, -86, 4, -86, 4, 54, 32, -87, 1, 73, 27,
                        28, -96, 113, -59, -102, -31, -17, 58, 34, 18, 105, 109, 109, -3, 102, 78,
                        78, 14, 5, 5, 5, -97, 10, -64, -30, -59, 101, -20, -85, -1, 1, -39, -77, 75,
                        -16, -46, 51, 49, 34, -95, 105, 2, -31, 109, -8, 67, -104, 103, -13, -85, 2,
                        46, 53, -73, -34, -99, -124, 95, 7, 78, 23, 22, 22, 122, 103, -50, -100, 33,
                        26, -115, 62, 48, -120, 103, 106, 107, -39, -77, -17, 0, 51, -98, 110, 34,
                        25, -8, -8, 41, -21, -109, 54, -68, 90, -85, -8, 54, 32, 97, 125, 124, 13,
                        10, 12, 114, -34, 54, -82, -72, -93, 10, 60, -32, -113, -82, -111, -46, 83,
                        103, -50, 82, 82, 82, -14, -64, 32, -14, -90, 79, -25, 70, -58, 99, 76, 94,
                        -72, -127, 100, -32, -109, -76, 74, 114, 24, -120, -64, 42, 73, 27, -112,
                        12, -4, -113, -126, -58, -22, -121, -17, -82, -126, -92, -84, 61, 113, -126,
                        -7, 107, 40, 45, 45, 101, -51, -102, -89, 31, 24, 64, -29, 75, 47, 113, -13,
                        -17, 127, 32, -51, -115, 16, 17, -63, 51, -126, 39, -31, 52, 34, 56, 34, 56,
                        98, 48, 70, 114, 36, 22, 95, 123, 55, 0, 76, 95, -41, 79, -68, 71, -53, 72,
                        47, -83, -27, -64, -127, -3, -28, -28, -28, -116, 123, -13, 41, 83, -90, 80,
                        92, 92, -52, 67, -113, 45, -60, -63, -30, 25, 33, 34, -110, -86, -116, 112,
                        115, 35, -126, 99, 4, 87, 28, 68, -28, -71, 33, 0, -79, 56, -60, -30, 69,
                        70, 76, -70, -29, -91, -45, -5, -89, 125, -44, -44, -44, -48, -39, -39, 57,
                        110, 0, -101, 55, 111, 14, -61, -80, 104, 3, -58, 38, 113, 83, -106, 71, 82,
                        -106, -69, 34, -120, -128, 65, 48, 98, 48, 98, 38, 19, 123, -27, 75, 33,
                        -81, 94, 106, 70, -98, -8, -18, 15, 93, 113, 22, 120, 70, -48, -82, 127,
                        113, -31, 116, 19, 37, -91, 11, -103, 54, 109, -38, -72, 0, 20, 20, 20, 112,
                        -7, -14, 101, 90, 95, -35, -53, -44, -126, 106, -84, 6, 32, 18, 50, 36, 96,
                        83, 83, 7, -90, 90, -84, -14, -2, 96, 8, 68, -7, -102, 17, 65, -84, 37, -29,
                        91, -49, -30, 21, 124, -97, -94, -94, 34, 54, 108, -40, 48, 110, 47, 52, 53,
                        53, 49, 37, 103, 34, 87, -114, -1, 24, -49, 75, -61, 8, 56, 8, 14, -126, 73,
                        -71, 91, 6, -90, 24, 68, -8, -22, 16, 0, -111, 71, -62, 90, 85, -60, 79,
                        -112, -15, -27, 39, -103, -70, -22, 69, -10, -19, 111, 36, 47, 111, -6, -72,
                        -61, -47, -34, -34, -50, -57, -17, -66, -55, 7, 23, -114, 98, -60, 32, 70,
                        16, 3, -58, 8, -110, -30, 7, 73, -123, 67, -112, 25, -61, -109, 112, -46,
                        16, 60, 0, -117, -105, 57, -103, 71, -42, 54, -47, -107, 62, -117, -36, -36,
                        92, 14, 29, 58, 116, 95, 0, -39, -39, -39, -76, -99, 59, -57, -11, 55, 126,
                        -51, 39, -99, 87, 16, -43, -112, -124, 0, 17, 13, 65, -96, -120, 10, 10,
                        -103, -26, 126, 90, -87, 65, -64, 23, -54, 54, 49, -93, -94, -98, 85, -85,
                        86, 81, 86, 86, 70, 34, -111, 24, -13, -75, -7, -13, -25, -77, 107, -41, 46,
                        58, 14, -81, -69, -81, 20, 15, 7, 112, 115, 40, 67, -62, 7, -102, 74, -114,
                        32, -39, -57, -43, -33, 53, -112, -105, -105, 71, 69, 69, 69, -54, -118,
                        -111, 71, 16, 4, -76, -76, -76, 112, -5, -10, -19, -112, 92, 122, -69, 82,
                        105, 8, -86, 2, -86, -96, -126, -118, 2, 116, 15, 54, 36, -86, 92, 81, -76,
                        64, 85, 66, 93, -73, 6, 43, -118, 85, 33, -39, -45, 5, -64, -50, -99, 59,
                        -87, -86, -86, 26, -45, -86, -74, -74, 54, 74, 75, 75, -103, -16, -71, -103,
                        -52, -88, -88, -57, -103, -16, 89, 124, -33, -57, -38, -127, 126, 97, -96,
                        10, 64, -47, 107, -125, 30, 80, -47, 55, -83, -22, 96, -39, 4, -124, -117,
                        3, 5, -109, -103, -61, 23, -53, -21, 88, -74, 108, 25, 51, 103, -50, -92,
                        -67, -67, 125, 84, 0, 69, 69, 69, -20, -40, -79, -125, -98, 15, -81, 50,
                        -15, -13, 79, 16, 88, -97, 0, -67, -85, 12, 7, -63, -100, -105, 97, 26, -3,
                        13, -49, 56, 45, -95, -122, 27, 28, 99, -120, 10, 68, -116, 33, 98, -124,
                        -88, 17, 60, -57, -27, -3, -42, -3, 124, 112, -95, -119, -54, -54, 74, 14,
                        30, 60, 72, 86, 86, -42, -120, 64, -106, 44, 89, 66, -53, 95, 47, 51, 61,
                        -10, 34, -67, -119, 4, 9, -85, 36, -84, -59, 87, -59, 15, 44, -3, 54, -119,
                        111, -3, -4, 59, -126, -23, -84, 62, -46, 27, 49, -111, 52, -49, 24, 92, 71,
                        112, -59, 16, 53, 66, 100, -128, -45, -115, -32, 57, 14, -74, -9, 38, -1,
                        56, -79, -125, -82, -21, 127, 99, -21, -42, -83, 52, 52, 52, -116, 8, 34,
                        55, 119, 50, 61, 15, -51, 37, 123, -31, 51, -12, 39, 19, 4, 86, -15, -43,
                        -110, 12, 2, -6, 109, -78, -45, 30, 92, -98, 123, 71, 21, 88, -43, -97, 6,
                        26, 96, 85, -79, 22, 124, 85, 18, -86, 36, -122, -87, 90, 50, 8, 32, -102,
                        -59, -84, -89, 118, 50, -89, -6, 121, -74, -17, 126, -127, -52, -116, -119,
                        28, 59, 118, -20, 30, 0, 23, 47, 94, -94, -5, -19, 83, 116, 119, -100, 14,
                        67, -112, 82, 68, 95, 3, 84, -75, 97, -60, -90, -44, -84, 62, -46, 23, 53,
                        110, -44, 51, 46, 38, 37, 34, -34, 48, 15, -72, 34, -72, 66, 40, 46, -128,
                        -29, -91, -47, -7, 86, 51, -17, -67, -79, -113, -4, -4, 124, -102, -102,
                        -102, -104, 53, 107, -42, -32, -9, 78, -98, 60, 73, 89, 89, 25, 89, -53,
                        127, -125, 102, -28, -122, 61, 65, -112, -4, 111, -48, -72, 60, -25, 30, 53,
                        76, 121, -95, 50, 105, 45, -66, 90, -84, 85, 108, -54, -14, -60, -64, -43,
                        42, -3, 22, -6, -84, -46, -81, 74, 79, -94, -113, -52, -57, -53, -103, -77,
                        -2, 117, -82, 7, 83, -104, 61, 123, 54, -79, 88, 108, -112, 43, 22, 47, 94,
                        -52, -90, 77, -101, -72, 117, 116, 61, 65, -32, -109, -76, 62, 1, -74, -36,
                        -92, 122, 67, 25, -27, 96, -79, -41, 51, -50, 58, -49, -72, -72, -95, 126,
                        15, -22, -7, -128, -11, 14, -124, 52, -53, 16, 103, 40, -122, -60, -83, 78,
                        62, 58, -7, 51, -110, -99, -17, -80, 123, -9, 110, 106, 106, 106, 0, 88,
                        -80, 96, 1, 127, -71, -10, 49, 84, -18, -39, -94, -65, 45, -33, 62, -6, -71,
                        32, -43, -61, 75, 44, 126, -36, 53, -50, 119, 92, 113, -15, -116, -63, -120,
                        96, 76, 40, 34, 3, -62, 98, -116, 12, -79, 22, 18, 122, 12, 80, 55, 74, -33,
                        -75, 54, 110, -97, -6, 5, 15, 79, 74, -25, -107, -8, 17, 22, 45, 90, 68,
                        118, 118, 22, -35, -73, -70, 127, -82, -16, -93, -79, 14, 38, -125, 32,
                        -120, -59, -9, -70, -30, -84, -13, -116, -63, 17, 7, 35, -126, 24, -63, 48,
                        32, 38, -124, 93, 103, -118, -55, 6, 8, -58, -94, -88, 85, -84, -15, -24,
                        107, -113, -29, -97, 127, -103, -62, -62, 66, -74, 111, -33, 78, 113, 113,
                        49, -64, 84, -32, -67, -47, 1, -36, 9, -94, -52, -120, -68, -26, -118, -109,
                        54, 0, -62, 72, -86, -49, 21, 101, 120, 12, 84, 67, -3, -73, -86, 88, -75,
                        -8, 97, 69, -35, -78, -35, 31, 126, 79, -101, -41, -81, 2, 86, -90, 86, -89,
                        3, 125, 99, 3, -72, 91, 56, 98, -15, -51, 70, -92, -50, -120, 73, 55, 24,
                        68, 66, 79, 48, -28, -128, 65, -122, 75, 29, -51, 110, -91, -114, 102, 123,
                        40, -33, 6, -81, -41, 1, 76, 6, 110, 2, -3, 99, -121, 96, -84, 17, -117, 23,
                        11, 82, 33, 48, 15, -111, -23, 2, -109, 82, -5, -33, 4, -67, -86, -54, 5,
                        -59, 30, -89, 113, -27, -97, -57, -13, -71, -1, 1, -117, 9, 35, 9, -5, 50,
                        107, 127, 0, 0, 0, 0, 73, 69, 78, 68, -82, 66, 96, -126
                    };

            String imageFileContents = new String(data);
            return imageFileContents;

        } else {
            String textFileContents =
                    "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Phasellus eu tortor efficitur,"
                            + "ultricies augue ut, gravida mauris. Orci varius natoque penatibus et magnis dis parturient montes,"
                            + "nascetur ridiculus mus. Fusce vitae odio pellentesque, molestie enim a, aliquam ligula. Suspendisse"
                            + "congue cursus tortor, porttitor semper nisl auctor vel. Duis non est nec leo pharetra ultricies."
                            + "In hac habitasse platea dictumst. Maecenas nunc odio, mollis non magna quis, congue maximus ex. Aliquam erat volutpat.";
            return textFileContents;
        }
    }

    @SuppressWarnings("rawtypes")
    private String generateFromObjectSchema(Map<String, Schema> properties) {
        StringBuilder json = new StringBuilder();
        boolean isFirst = true;
        json.append(SYNTAX.get(Element.OBJECT_BEGIN));
        for (Map.Entry<String, Schema> property : properties.entrySet()) {
            if (isFirst) {
                isFirst = false;
            } else {
                json.append(SYNTAX.get(Element.OUTER_SEPARATOR));
            }
            json.append(SYNTAX.get(Element.PROPERTY_CONTAINER));
            json.append(property.getKey());
            json.append(SYNTAX.get(Element.PROPERTY_CONTAINER));
            json.append(SYNTAX.get(Element.INNER_SEPARATOR));
            String value;
            if (dataGenerator.isSupported(property.getValue())) {
                value = dataGenerator.generateBodyValue(property.getKey(), property.getValue());
            } else {

                value =
                        generators
                                .getValueGenerator()
                                .getValue(
                                        property.getKey(),
                                        property.getValue().getType(),
                                        generate(property.getValue()));
            }
            json.append(value);
        }
        json.append(SYNTAX.get(Element.OBJECT_END));
        return json.toString();
    }

    private static String createJsonArrayWith(String jsonStr) {
        return SYNTAX.get(Element.ARRAY_BEGIN)
                + jsonStr
                + SYNTAX.get(Element.OUTER_SEPARATOR)
                + jsonStr
                + SYNTAX.get(Element.ARRAY_END);
    }

    private String generateJsonPrimitiveValue(Schema<?> schema) {
        return dataGenerator.generateBodyValue("", schema);
    }

    private static Schema<?> resolveComposedSchema(ComposedSchema schema) {

        if (schema.getOneOf() != null) {
            return schema.getOneOf().get(0);
        } else if (schema.getAnyOf() != null) {
            return schema.getAnyOf().get(0);
        }
        // Should not be reached, allOf schema is resolved by the parser
        LOG.error("Unknown composed schema type: " + schema);
        return null;
    }

    private static void resolveNotSchema(Schema<?> schema) {
        if (schema.getNot().getType().equals("string")) {
            schema.setType("integer");
        } else {
            schema.setType("string");
        }
    }

    @SuppressWarnings("serial")
    private static final Map<Element, String> FORMSYNTAX =
            Collections.unmodifiableMap(
                    new HashMap<Element, String>() {
                        {
                            put(Element.INNER_SEPARATOR, "=");
                            put(Element.OUTER_SEPARATOR, "&");
                        }
                    });

    @SuppressWarnings("rawtypes")
    public String generateForm(Schema<?> schema) {
        Map<String, Schema> properties = schema.getProperties();
        if (properties != null) {
            StringBuilder formData = new StringBuilder();
            for (Map.Entry<String, Schema> property : properties.entrySet()) {
                formData.append(urlEncode(property.getKey()));
                formData.append(FORMSYNTAX.get(Element.INNER_SEPARATOR));
                formData.append(
                        urlEncode(
                                dataGenerator.generateValue(
                                        property.getKey(), property.getValue(), true)));
                formData.append(FORMSYNTAX.get(Element.OUTER_SEPARATOR));
            }
            return formData.substring(0, formData.length() - 1);
        }
        return "";
    }

    @SuppressWarnings("serial")
    private static final Map<Element, String> MULTIPARTSYNTAX =
            new HashMap<Element, String>() {
                {
                    put(Element.OBJECT_BEGIN, "");
                    put(Element.INNER_SEPARATOR, ": ");
                    put(Element.OUTER_SEPARATOR, "; ");
                    put(Element.PROPERTY_CONTAINER, "\"");
                }
            };

    @SuppressWarnings("rawtypes")
    public String generateMultiPart(Schema<?> schema, Map<String, Encoding> encoding) {
        String boundary = UUID.randomUUID().toString();
        MULTIPARTSYNTAX.replace(Element.OBJECT_BEGIN, boundary);
        Map<String, Schema> properties = schema.getProperties();
        if (properties != null) {
            StringBuilder multipartData = new StringBuilder();
            for (Map.Entry<String, Schema> property : properties.entrySet()) {
                Schema propertySchema = property.getValue();
                multipartData.append("--" + MULTIPARTSYNTAX.get(Element.OBJECT_BEGIN));
                multipartData.append("\r\n");
                multipartData.append("Content-Disposition");
                multipartData.append(MULTIPARTSYNTAX.get(Element.INNER_SEPARATOR));
                multipartData.append("form-data");
                multipartData.append(MULTIPARTSYNTAX.get(Element.OUTER_SEPARATOR));
                multipartData.append("name=");
                multipartData.append(MULTIPARTSYNTAX.get(Element.PROPERTY_CONTAINER));
                multipartData.append(property.getKey());
                multipartData.append(MULTIPARTSYNTAX.get(Element.PROPERTY_CONTAINER));
                if (propertySchema instanceof BinarySchema) {
                    multipartData.append(MULTIPARTSYNTAX.get(Element.OUTER_SEPARATOR));
                    multipartData.append("filename=");
                    multipartData.append(MULTIPARTSYNTAX.get(Element.PROPERTY_CONTAINER));
                    multipartData.append("SampleZAPFile");
                    multipartData.append(MULTIPARTSYNTAX.get(Element.PROPERTY_CONTAINER));
                }
                multipartData.append("\r\n");

                Encoding propertyEncoding;
                String propertyContentType = null;
                Map<String, Header> propertyHeaders = null;

                if (encoding != null) {
                    propertyEncoding = encoding.get(property.getKey());
                    if (propertyEncoding != null) {
                        propertyContentType = propertyEncoding.getContentType();
                        propertyHeaders = propertyEncoding.getHeaders();
                    }
                }

                if (propertyContentType == null) {
                    propertyContentType = getPropertyContentType(propertySchema);
                }
                multipartData.append("Content-Type");
                multipartData.append(MULTIPARTSYNTAX.get(Element.INNER_SEPARATOR));
                multipartData.append(propertyContentType);
                multipartData.append("\r\n");

                if (propertyHeaders != null) {
                    for (Map.Entry<String, Header> header : propertyHeaders.entrySet()) {
                        String headerName = header.getKey();
                        multipartData.append(headerName);
                        multipartData.append(MULTIPARTSYNTAX.get(Element.INNER_SEPARATOR));
                        multipartData.append(
                                dataGenerator.generateValue(
                                        headerName, header.getValue().getSchema(), false));
                        multipartData.append("\r\n");
                    }
                }

                multipartData.append("\r\n");
                if (propertyContentType.contains("image")) {
                    multipartData.append(
                            generateFromBinarySchema(((BinarySchema) propertySchema), true));
                } else {
                    multipartData.append(generate(propertySchema));
                }
                multipartData.append("\r\n");
            }
            multipartData.append("--" + MULTIPARTSYNTAX.get(Element.OBJECT_BEGIN) + "--");
            return multipartData.toString();
        }
        return "";
    }

    private static String getPropertyContentType(Schema<?> schema) {
        String type;

        if (schema instanceof ObjectSchema) {
            type = "application/json";
        } else if (schema instanceof BinarySchema) {
            type = "application/octet-stream";
        } else if (schema instanceof ArraySchema) {
            type = getPropertyContentType(((ArraySchema) schema).getItems());
        } else {
            type = "text/plain";
        }
        return type;
    }

    private static String urlEncode(String string) {
        try {
            return URLEncoder.encode(string, StandardCharsets.UTF_8.name());
        } catch (UnsupportedEncodingException ignore) {
            // Shouldn't happen, standard charset.
            return "";
        }
    }
}
