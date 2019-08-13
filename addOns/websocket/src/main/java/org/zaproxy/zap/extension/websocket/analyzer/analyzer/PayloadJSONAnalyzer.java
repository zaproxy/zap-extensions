/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2019 The ZAP Development Team
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
package org.zaproxy.zap.extension.websocket.analyzer.analyzer;

import static org.zaproxy.zap.extension.websocket.analyzer.structural.SimpleNameValuePair.*;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.TypeAdapter;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import java.io.IOException;
import java.util.Stack;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.log4j.Logger;
import org.zaproxy.zap.extension.websocket.WebSocketMessage;
import org.zaproxy.zap.extension.websocket.WebSocketMessageDTO;
import org.zaproxy.zap.extension.websocket.analyzer.structural.SimpleNameValuePair;
import org.zaproxy.zap.extension.websocket.analyzer.structure.PayloadStructure;
import org.zaproxy.zap.extension.websocket.analyzer.structure.PlaceholderPayloadStructure;
import org.zaproxy.zap.extension.websocket.utility.InvalidUtf8Exception;

public class PayloadJSONAnalyzer implements PayloadAnalyzer {

    private static final Logger LOGGER = Logger.getLogger(PayloadJSONAnalyzer.class);

    private static final String NAME = PayloadJSONAnalyzer.class.getSimpleName();
    private static final int ID = 10000010;

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public int getId() {
        return ID;
    }

    @Override
    public PayloadStructure parse(WebSocketMessageDTO message) {
        if (message.opcode != WebSocketMessage.OPCODE_TEXT) {
            return null;
        }

        PlaceholderPayloadStructure.Builder structureBuilder = null;
        try {
            structureBuilder =
                    getGson(message)
                            .fromJson(
                                    message.getReadablePayload(),
                                    PlaceholderPayloadStructure.Builder.class);
            structureBuilder.setOriginalMessage(message);
        } catch (InvalidUtf8Exception e) {
            LOGGER.info("Can't convert WebSocket payload to readable format", e);
        } catch (Exception e) {
            LOGGER.error(e);
            e.printStackTrace();
            structureBuilder = null;
        }
        return structureBuilder == null ? null : structureBuilder.build();
    }

    private Gson getGson(WebSocketMessageDTO message) throws InvalidUtf8Exception {
        return getGsonBuilder(message).create();
    }

    private GsonBuilder getGsonBuilder(WebSocketMessageDTO message) throws InvalidUtf8Exception {
        return new GsonBuilder()
                .registerTypeAdapter(
                        PlaceholderPayloadStructure.Builder.class,
                        new PayloadStructureTypeAdapter(message))
                .setLenient();
    }

    private class PayloadStructureTypeAdapter
            extends TypeAdapter<PlaceholderPayloadStructure.Builder> {

        private final String QUATATION_MARK = "\"";
        private final String ID_REGEX_PREFIX = QUATATION_MARK;
        private final String ID_REGEX_SUFFIX = "\"(\\s)*:";

        private final String ARRAY_NAME_BEGIN = "[";
        private final String ARRAY_NAME_END = "]";

        private String payload;
        private int position = 0;
        PlaceholderPayloadStructure.Builder structureBuilder;

        PayloadStructureTypeAdapter(WebSocketMessageDTO message) throws InvalidUtf8Exception {
            payload = message.getReadablePayload();
            structureBuilder = new PlaceholderPayloadStructure.Builder(message);
        }

        @Override
        public void write(JsonWriter out, PlaceholderPayloadStructure.Builder value) {
            // Do nothing
        }

        @Override
        public PlaceholderPayloadStructure.Builder read(JsonReader in) throws IOException {

            in.setLenient(true);
            Stack<String> names = new Stack<>();

            while (in.hasNext()) {
                switch (in.peek()) {
                    case BEGIN_OBJECT:
                        readObject(
                                names.isEmpty() ? OBJECT_NAME : names.pop(), in, structureBuilder);
                        break;
                    case NAME:
                        String name = in.nextName();
                        consumeName(name);
                        names.push(name);
                        break;
                    case BEGIN_ARRAY:
                        readArray(names.isEmpty() ? ARRAY_NAME : names.pop(), in, structureBuilder);
                        break;
                    case END_DOCUMENT:
                        return structureBuilder;
                    case NULL:
                    case BOOLEAN:
                    case NUMBER:
                    case STRING:
                        SimpleNameValuePair.Builder nameValue = new SimpleNameValuePair.Builder();
                        nameValue.setName(names.isEmpty() ? VAR_NAME : names.pop());
                        readValue(nameValue, in, structureBuilder);
                        break;
                    default:
                        throw new IllegalStateException("Unexpected value: " + in.peek());
                }
            }
            return structureBuilder;
        }

        private void readObject(
                String name, JsonReader in, PlaceholderPayloadStructure.Builder structureBuilder)
                throws IOException {
            try {
                in.beginObject();
            } catch (IOException e) {
                LOGGER.debug("This is not an object", e);
                return;
            }

            Stack<String> names = new Stack<>();

            while (in.hasNext()) {
                switch (in.peek()) {
                    case NAME:
                        names.push(in.nextName());
                        break;
                    case BEGIN_OBJECT:
                        readObject(names.isEmpty() ? name : names.pop(), in, structureBuilder);
                        break;
                    case END_OBJECT:
                        in.endObject();
                        return;
                    case END_DOCUMENT:
                        return;
                    case BEGIN_ARRAY:
                        readArray(names.isEmpty() ? name : names.pop(), in, structureBuilder);
                        break;
                    default:
                        SimpleNameValuePair.Builder nameValueBuilder =
                                new SimpleNameValuePair.Builder();
                        nameValueBuilder.setName(names.isEmpty() ? name : names.pop());
                        readValue(nameValueBuilder, in, structureBuilder);
                }
            }
            in.endObject();
        }

        private void readArray(
                String name, JsonReader in, PlaceholderPayloadStructure.Builder structureBuilder)
                throws IOException {
            try {
                in.beginArray();
            } catch (IOException e) {
                LOGGER.debug("This is not an Array", e);
                return;
            }
            Stack<String> names = new Stack<>();
            int count = 0;
            while (in.hasNext()) {
                switch (in.peek()) {
                    case NAME:
                        String nextName = in.nextName();
                        consumeName(nextName);
                        names.push(nextName);
                        break;
                    case BEGIN_OBJECT:
                        readObject(names.isEmpty() ? name : names.pop(), in, structureBuilder);
                        break;
                    case BEGIN_ARRAY:
                        readArray(
                                name + ARRAY_NAME_BEGIN + count++ + ARRAY_NAME_END,
                                in,
                                structureBuilder);
                        break;
                    case END_ARRAY:
                        in.endArray();
                        return;
                    default:
                        SimpleNameValuePair.Builder nameValueBuilder =
                                new SimpleNameValuePair.Builder();
                        nameValueBuilder.setName(
                                name + ARRAY_NAME_BEGIN + count++ + ARRAY_NAME_END);
                        readValue(nameValueBuilder, in, structureBuilder);
                }
            }
            in.endArray();
        }

        private void readValue(
                SimpleNameValuePair.Builder nameValueBuilder,
                JsonReader in,
                PlaceholderPayloadStructure.Builder structureBuilder) {
            try {
                if (in.hasNext()) {
                    switch (in.peek()) {
                        case NUMBER:
                            try {
                                consumeValue(nameValueBuilder, in.nextInt());
                            } catch (NumberFormatException e) {
                                consumeValue(nameValueBuilder, in.nextDouble());
                            }
                            break;
                        case BOOLEAN:
                            consumeValue(nameValueBuilder, in.nextBoolean());
                            break;
                        case STRING:
                            consumeValue(nameValueBuilder, in.nextString());
                            break;
                        case NULL:
                            in.nextNull();
                            consumeNullValue(nameValueBuilder);
                            break;
                        default:
                            throw new IllegalStateException("Unexpected value: " + in.peek());
                    }
                }
            } catch (IOException e) {
                LOGGER.debug("Nothing to read", e);
            }
            structureBuilder.add(nameValueBuilder.build());
        }

        private static final String NULL_VALUE = "null";

        private static final String INTEGER_REGEX = "\\d+";
        private static final String DOUBLE_REGEX = "^[-+]?[0-9]*\\.?[0-9]+([eE][-+]?[0-9]+)?$";
        private static final String BOOLEAN_REGEX = "(true|false)";
        private static final String NULL_REGEX = NULL_VALUE;

        private SimpleNameValuePair.Builder consumeName(String name) {
            Matcher matcher =
                    Pattern.compile(ID_REGEX_PREFIX + Pattern.quote(name) + ID_REGEX_SUFFIX)
                            .matcher(payload);
            if (matcher.find(position)) {
                position = matcher.end();
            }
            throw new IllegalStateException("Can't consume name");
        }

        private SimpleNameValuePair.Builder consumeNullValue(SimpleNameValuePair.Builder builder)
                throws IllegalStateException {

            try {
                positioning(builder, NULL_REGEX);
                builder.setValue(NULL_VALUE, Type.NULL);
            } catch (IllegalStateException e) {
                throw new IllegalStateException(e.getMessage() + " null value");
            }
            return builder;
        }

        private SimpleNameValuePair.Builder consumeValue(
                SimpleNameValuePair.Builder builder, boolean value) {
            try {
                positioning(builder, BOOLEAN_REGEX);
                builder.setValue(value);
            } catch (IllegalStateException e) {
                throw new IllegalStateException(e.getMessage() + " Boolean value: " + value);
            }
            return builder;
        }

        private SimpleNameValuePair.Builder consumeValue(
                SimpleNameValuePair.Builder builder, double value) throws IllegalStateException {
            try {
                builder.setValue(positioning(builder, DOUBLE_REGEX).group(), Type.DOUBLE);
            } catch (IllegalStateException e) {
                throw new IllegalStateException(e.getMessage() + " Double value: " + value);
            }
            return builder;
        }

        private SimpleNameValuePair.Builder consumeValue(
                SimpleNameValuePair.Builder builder, int value) throws IllegalStateException {
            try {
                positioning(builder, INTEGER_REGEX);
                builder.setValue(value);
            } catch (IllegalStateException e) {
                throw new IllegalStateException(e.getMessage() + " Integer value: " + value);
            }
            return builder;
        }

        private SimpleNameValuePair.Builder consumeValue(
                SimpleNameValuePair.Builder builder, String value) throws IllegalStateException {
            try {
                positioning(builder, QUATATION_MARK + Pattern.quote(value) + QUATATION_MARK);
                builder.setValue(QUATATION_MARK + value + QUATATION_MARK);
            } catch (IllegalStateException e) {
                throw new IllegalStateException(e.getMessage() + " String value: " + value);
            }
            return builder;
        }

        private Matcher positioning(SimpleNameValuePair.Builder builder, String pattern)
                throws IllegalStateException {
            Matcher matcher = Pattern.compile(pattern).matcher(payload);
            if (matcher.find(position)) {
                builder.setPosition(matcher.start());
                position = matcher.end();
                return matcher;
            }
            throw new IllegalStateException("Can't consume");
        }
    }
}
