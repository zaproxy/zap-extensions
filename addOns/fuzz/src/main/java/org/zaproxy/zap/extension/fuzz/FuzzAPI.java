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
package org.zaproxy.zap.extension.fuzz;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import net.sf.json.JSONObject;
import net.sf.json.JSONSerializer;
import org.apache.commons.io.IOUtils;
import org.apache.log4j.Logger;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.db.RecordHistory;
import org.parosproxy.paros.db.TableHistory;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.api.*;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.HttpFuzzer;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.HttpFuzzerHandler;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.HttpFuzzerMessageProcessor;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.HttpFuzzerOptions;
import org.zaproxy.zap.extension.fuzz.messagelocations.*;
import org.zaproxy.zap.extension.fuzz.payloads.DefaultPayload;
import org.zaproxy.zap.extension.fuzz.payloads.PayloadGeneratorMessageLocation;
import org.zaproxy.zap.extension.fuzz.payloads.generator.DefaultStringPayloadGenerator;
import org.zaproxy.zap.extension.httppanel.Message;
import org.zaproxy.zap.model.HttpMessageLocation;
import org.zaproxy.zap.model.MessageLocation;
import org.zaproxy.zap.model.TextHttpMessageLocation;
import org.zaproxy.zap.utils.Pair;
import org.zaproxy.zap.utils.ResettableAutoCloseableIterator;

public class FuzzAPI extends ApiImplementor {
    /* Api NAME */
    private static final String PREFIX = "fuzz";
    private static final String SECTION_SIGN = "§";
    private static final String ESCAPE_CHARACTER = "\\";
    private ExtensionFuzz extension;
    private static final Logger LOGGER = Logger.getLogger(FuzzAPI.class);

    /* Default values for Http Fuzzer */
    private HttpFuzzerHandler httpFuzzerHandler;

    private static final String ACTION_TEST = "test";
    private static final String ACTION_SIMPLE_HTTP_FUZZER = "simpleHttpFuzzer";
    private static final String ACTION_SET_HTTP_FUZZ_OPTIONS = "setHttpFuzzerOptions";
    private static final String ACTION_RESET_DEFAULT_HTTP_FUZZ_OPTIONS =
            "resetHttpFuzzOptionsToDefault";
    private static final String ACTION_MULTIPLE_PAYLOAD_FUZZER = "multiplePayloadFuzzerOptions";

    public FuzzAPI(ExtensionFuzz ext) {
        this.extension = ext;
        this.addApiAction(new ApiAction(ACTION_SIMPLE_HTTP_FUZZER, new String[] {"id"}));
        this.addApiAction(new ApiAction(ACTION_TEST, new String[] {}));
    }

    @Override
    public String getPrefix() {
        return PREFIX;
    }

    @Override
    public ApiResponse handleApiAction(String name, JSONObject params) throws ApiException {
        switch (name) {
            case ACTION_TEST:
                Pair<HttpMessage, List<TextHttpMessageLocation>> p =
                        generateHttpMessageLocationsFromHttpMessageJsonInput(
                                "/home/dennis/zaproxy-proj/zap-extensions/sample_fuzz_location_message.json");
                System.out.println(p.first.getRequestBody().toString());
                System.out.println(p.first.getRequestHeader().toString());
                for (int i = 0; i < p.second.size(); i++) {
                    System.out.println(
                            p.second.get(i).getStart()
                                    + " "
                                    + p.second.get(i).getEnd()
                                    + " "
                                    + p.second.get(i).getLocation());
                }

                break;
            case ACTION_SIMPLE_HTTP_FUZZER:
                TableHistory tableHistory = Model.getSingleton().getDb().getTableHistory();
                RecordHistory recordHistory =
                        getRecordHistory(tableHistory, getParam(params, "id", -1));

                httpFuzzerHandler = new HttpFuzzerHandler();

                List<PayloadGeneratorMessageLocation<?>> fuzzLocations =
                        createFuzzLocations(
                                recordHistory.getHttpMessage(),
                                HttpMessageLocation.Location.REQUEST_BODY,
                                9,
                                14,
                                "/home/dennis/zaproxy-proj/temp_payloads.txt");
                List<HttpFuzzerMessageProcessor> messageProcessors = Collections.emptyList();
                HttpFuzzerOptions httpFuzzerOptions =
                        getOptions(extension.getDefaultFuzzerOptions());

                HttpFuzzer httpFuzzer =
                        createFuzzer(
                                "some name",
                                recordHistory.getHttpMessage(),
                                fuzzLocations,
                                httpFuzzerOptions,
                                messageProcessors);
                System.out.println("Starting fuzzer");
                extension.runFuzzer(httpFuzzerHandler, httpFuzzer);

                break;

            default:
                throw new ApiException(ApiException.Type.BAD_ACTION);
        }

        return ApiResponseElement.OK;
    }

    private RecordHistory getRecordHistory(TableHistory tableHistory, Integer id)
            throws ApiException {
        RecordHistory recordHistory;
        try {
            recordHistory = tableHistory.read(id);
        } catch (HttpMalformedHeaderException | DatabaseException e) {
            throw new ApiException(ApiException.Type.INTERNAL_ERROR, e);
        }
        if (recordHistory == null) {
            throw new ApiException(ApiException.Type.DOES_NOT_EXIST, Integer.toString(id));
        }
        return recordHistory;
    }

    private List<PayloadGeneratorMessageLocation<?>> createFuzzLocations(
            HttpMessage httpMessage,
            HttpMessageLocation.Location location,
            int start,
            int end,
            String payloadPath) {
        TextHttpMessageLocation textHttpMessageLocation =
                createTextHttpMessageLocationObjects(start, end, location);
        List<String> allLines = new ArrayList<>();
        try {
            allLines = Files.readAllLines(Paths.get(payloadPath));
        } catch (IOException e) {
            e.printStackTrace();
        }

        List<PayloadGeneratorMessageLocation<?>> fuzzLocations =
                createPayloadGeneratorMessageLocationList(
                        textHttpMessageLocation, httpMessage, allLines);

        return fuzzLocations;
    }

    private List<PayloadGeneratorMessageLocation<?>> createPayloadGeneratorMessageLocationList(
            HttpMessageLocation messageLocation, HttpMessage message, List<String> payloads) {
        List<PayloadGeneratorMessageLocation<?>> payloadGeneratorMessageLocationList =
                new ArrayList<>();
        DefaultStringPayloadGenerator payloadGenerator;
        payloadGenerator = new DefaultStringPayloadGenerator(payloads);
        ResettableAutoCloseableIterator<DefaultPayload> resettableAutoCloseableIterator =
                payloadGenerator.iterator();
        PayloadGeneratorMessageLocation<?> payloadGeneratorMessageLocation =
                new PayloadGeneratorMessageLocation<>(
                        messageLocation, payloads.size(), resettableAutoCloseableIterator);
        payloadGeneratorMessageLocationList.add(payloadGeneratorMessageLocation);
        return payloadGeneratorMessageLocationList;
    }

    private TextHttpMessageLocation createTextHttpMessageLocationObjects(
            int start, int end, HttpMessageLocation.Location location) {
        return new TextHttpMessageLocation() {
            @Override
            public int getStart() {
                return start;
            }

            @Override
            public int getEnd() {
                return end;
            }

            @Override
            public Location getLocation() {
                return location;
            }

            @Override
            public Class<? extends Message> getTargetMessageClass() {
                return null;
            }
            // There is no need for these but can be fixed
            // All of the functions below no need probably
            @Override
            public String getDescription() {
                return null;
            }

            @Override
            public String getValue() {
                return null;
            }

            @Override
            public boolean overlaps(MessageLocation otherLocation) {
                return false;
            }

            @Override
            public int compareTo(MessageLocation messageLocation) {
                return 0;
            }
        };
    }

    private HttpFuzzer createFuzzer(
            String name,
            HttpMessage message,
            List<PayloadGeneratorMessageLocation<?>> fuzzLocations,
            HttpFuzzerOptions options,
            List<HttpFuzzerMessageProcessor> processors) {
        if (fuzzLocations.isEmpty()) {
            return null;
        }

        MessageLocationReplacer<HttpMessage> replacer =
                MessageLocationReplacers.getInstance()
                        .getMLR(HttpMessage.class, TextHttpMessageLocation.class);

        replacer.init(message);

        MultipleMessageLocationsReplacer<HttpMessage> multipleMessageLocationsReplacer;
        if (MessageLocationsReplacementStrategy.DEPTH_FIRST
                == options.getPayloadsReplacementStrategy()) {
            multipleMessageLocationsReplacer = new MultipleMessageLocationsDepthFirstReplacer<>();
        } else {
            multipleMessageLocationsReplacer = new MultipleMessageLocationsBreadthFirstReplacer<>();
        }
        SortedSet<MessageLocationReplacementGenerator<?, ?>> messageLocationReplacementGenerators =
                new TreeSet<>();

        for (PayloadGeneratorMessageLocation<?> fuzzLocation : fuzzLocations) {
            messageLocationReplacementGenerators.add(fuzzLocation);
        }
        multipleMessageLocationsReplacer.init(replacer, messageLocationReplacementGenerators);

        return new HttpFuzzer(
                name,
                options,
                message,
                (List<MessageLocationReplacementGenerator<?, MessageLocationReplacement<?>>>)
                        (ArrayList) fuzzLocations,
                multipleMessageLocationsReplacer,
                processors);
    }

    public HttpFuzzerOptions getOptions(FuzzerOptions baseOptions) {
        return new HttpFuzzerOptions(baseOptions, false, false, 100, false);
    }

    public Pair<HttpMessage, List<TextHttpMessageLocation>>
            generateHttpMessageLocationsFromHttpMessageJsonInput(String jsonPath)
                    throws IllegalFormatException {
        List<TextHttpMessageLocation> textHttpMessageLocationList = new ArrayList<>();
        File initialFile = new File(jsonPath);
        InputStream is = null;
        try {
            is = new FileInputStream(initialFile);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        String jsonTxt = null;
        try {
            jsonTxt = IOUtils.toString(is);
        } catch (IOException e) {
            e.printStackTrace();
        }

        JSONObject jsonObject = (JSONObject) JSONSerializer.toJSON(jsonTxt);
        JSONObject messageObject = (JSONObject) jsonObject.get("message");
        List<Integer> headerFuzzLocations =
                findCharactersInsideString(messageObject.get("requestHeader").toString());
        List<Integer> bodyFuzzLocations =
                findCharactersInsideString(messageObject.get("requestBody").toString());
        // Remove the SECTION_SIGN character not needed anymore
        if (((headerFuzzLocations.size() & 1) != 0) || ((bodyFuzzLocations.size() & 1) != 0)) {
            throw new IllegalArgumentException(
                    "Invalid number of section characters in JSON Input");
        }
        for (int i = 0; i < headerFuzzLocations.size(); i += 2) {
            textHttpMessageLocationList.add(
                    createTextHttpMessageLocationObjects(
                            headerFuzzLocations.get(i),
                            headerFuzzLocations.get(i + 1),
                            TextHttpMessageLocation.Location.REQUEST_HEADER));
        }
        for (int i = 0; i < bodyFuzzLocations.size(); i += 2) {
            textHttpMessageLocationList.add(
                    createTextHttpMessageLocationObjects(
                            bodyFuzzLocations.get(i),
                            bodyFuzzLocations.get(i + 1),
                            TextHttpMessageLocation.Location.REQUEST_BODY));
        }
        HttpMessage httpMessage = createHttpMessageFromJsonMessageObject(messageObject);
        return new Pair<>(httpMessage, textHttpMessageLocationList);
    }

    private HttpMessage createHttpMessageFromJsonMessageObject(JSONObject messageObject) {
        HttpMessage message = null;
        String requestHeader =
                messageObject.get("requestHeader").toString().replace(SECTION_SIGN, "");
        byte[] requestBodyObject =
                messageObject.get("requestBody").toString().replace(SECTION_SIGN, "").getBytes();
        String responseHeader = messageObject.get("responseHeader").toString();
        byte[] responseBodyObject = messageObject.get("responseBody").toString().getBytes();
        try {
            message =
                    new HttpMessage(
                            requestHeader, requestBodyObject, responseHeader, responseBodyObject);
        } catch (HttpMalformedHeaderException e) {
            e.printStackTrace();
        }
        return message;
    }

    private List<Integer> findCharactersInsideString(String string) {
        System.out.println(string);
        List<Integer> characterList = new ArrayList<>();
        for (int i = 0; i < string.length(); i++) {
            if (string.charAt(i) == FuzzAPI.SECTION_SIGN.charAt(0)) {
                if (notEscaped(string, i)) {
                    characterList.add(i - characterList.size());
                }
            }
        }
        return characterList;
    }
    // Check if the signum character was escaped
    // TODO implement this
    private boolean notEscaped(String string, int i) {
        return true;
    }
}
