/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.zaproxy.zap.extension.jsonview.internal;

import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;

public final class JsonFormatter {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final ObjectWriter PRETTY_PRINTER =
            OBJECT_MAPPER.writerWithDefaultPrettyPrinter();

    private JsonFormatter() {}

    /**
     * Tells whether or not the given data is JSON.
     *
     * @param data the data to check.
     * @return {@code true} if the given data is JSON, {@code false} otherwise.
     */
    public static boolean isJson(String data) {
        if (isBlank(data)) {
            return true;
        }

        try {
            parse(data);
            return true;
        } catch (JacksonException e) {
            return false;
        }
    }

    private static boolean isBlank(String data) {
        return data == null || data.isBlank();
    }

    private static Object parse(String data) throws JacksonException {
        return OBJECT_MAPPER.readValue(data, Object.class);
    }

    /**
     * Formats the given JSON.
     *
     * <p>If not valid JSON it is returned without any modifications.
     *
     * @param data the JSON to format.
     * @return the formatted JSON, or the given data if not JSON.
     */
    public static String toFormattedJson(String data) {
        if (isBlank(data)) {
            return data;
        }

        try {
            var object = parse(data);
            return PRETTY_PRINTER.writeValueAsString(object);
        } catch (Exception e) {
            return data;
        }
    }
}
