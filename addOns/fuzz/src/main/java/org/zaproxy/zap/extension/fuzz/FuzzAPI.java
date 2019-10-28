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
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import net.sf.json.JSONSerializer;
import org.apache.commons.io.IOUtils;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
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

    private static final String PARAM_MESSAGE_ID = "messageId";
    private static final String PARAM_LOCATION = "location";
    private static final String PARAM_PAYLOAD = "payload";
    private static final String PARAM_FUZZ_HEADER = "fuzzHeader";
    private static final String PARAM_FUZZER_ID = "fuzzerId";

    private static final Logger LOGGER = Logger.getLogger(FuzzAPI.class);

    /* Default values for Http Fuzzer */
    private HttpFuzzerHandler httpFuzzerHandler;
    private static final String ACTION_TEST = "test";
    private static final String ACTION_SIMPLE_HTTP_FUZZER = "simpleHttpFuzzer";
    private static final String ACTION_SET_HTTP_FUZZ_OPTIONS = "setHttpFuzzerOptions";
    private static final String ACTION_RESET_DEFAULT_HTTP_FUZZ_OPTIONS =
            "resetHttpFuzzOptionsToDefault";
    private static final String ACTION_MULTIPLE_PAYLOAD_FUZZER = "multiplePayloadFuzzerOptions";
    private static final String VIEW_GET_FUZZER_STATUS = "fuzzerStatus";

    public FuzzAPI(ExtensionFuzz ext) {
        this.extension = ext;
        this.addApiAction(
                new ApiAction(
                        ACTION_SIMPLE_HTTP_FUZZER,
                        new String[] {
                            PARAM_MESSAGE_ID, PARAM_LOCATION, PARAM_PAYLOAD, PARAM_FUZZ_HEADER
                        }));
        this.addApiAction(new ApiAction(ACTION_TEST, new String[] {}));
        this.addApiView(new ApiView(VIEW_GET_FUZZER_STATUS, new String[] {PARAM_FUZZER_ID}));
    }

    @Override
    public String getPrefix() {
        return PREFIX;
    }

    @Override
    public ApiResponse handleApiView(String name, JSONObject params) throws ApiException {
        ApiResponse result = null;
        switch (name) {
            case VIEW_GET_FUZZER_STATUS:
                int fuzzerId = getParam(params, PARAM_FUZZER_ID, -1);
                List<HttpFuzzer> fuzzersList = extension.getFuzzers(HttpFuzzer.class);
                HttpFuzzer fuzzer = null;
                for (HttpFuzzer f : fuzzersList) {
                    if (f.getScanId() == fuzzerId) {
                        fuzzer = f;
                        break;
                    }
                }
                if (fuzzer != null) {
                    int progress = 0;
                    if (fuzzer.isStopped()) {
                        progress = 100;
                    } else {
                        progress = fuzzer.getProgress();
                    }
                    return new ApiResponseElement("progress", Integer.toString(progress));
                }
                return ApiResponseElement.FAIL;
            default:
                throw new ApiException(ApiException.Type.BAD_VIEW);
        }
    }

    @Override
    public ApiResponse handleApiAction(String name, JSONObject params) throws ApiException {
        switch (name) {
            case ACTION_TEST:
                //                Pair<HttpMessage, List<TextHttpMessageLocation>> p =
                //                        generateHttpMessageLocationsFromHttpMessageJsonInput(
                //
                // "/home/dennis/zaproxy-proj/zap-extensions/sample_fuzz_location_message.json");
                //                System.out.println(p.first.getRequestBody().toString());
                //                System.out.println(p.first.getRequestHeader().toString());
                //                List<PayloadGeneratorMessageLocation<?>>
                // fuzzLocationsAdvancedFuzzer =
                //                        new ArrayList<>();
                //                for (int i = 0; i < p.second.size(); i++) {
                //                    System.out.println(
                //                            p.second.get(i).getStart()
                //                                    + " "
                //                                    + p.second.get(i).getEnd()
                //                                    + " "
                //                                    + p.second.get(i).getLocation());
                //                    // Using the same payload for all locations
                //                    fuzzLocationsAdvancedFuzzer.addAll(
                //                            createFuzzLocations(
                //                                    p.second.get(i).getLocation(),
                //                                    p.second.get(i).getStart(),
                //                                    p.second.get(i).getEnd(),
                //
                // "/home/dennis/zaproxy-proj/zap-extensions/sample_payload.txt"));
                //                }
                //                List<HttpFuzzerMessageProcessor> messageProcessors =
                // Collections.emptyList();
                //                HttpFuzzerOptions httpFuzzerOptions =
                //                        getOptions(extension.getDefaultFuzzerOptions());
                //                HttpFuzzerHandler httpFuzzerHandler = new HttpFuzzerHandler();
                //                HttpFuzzer httpFuzzer =
                //                        createFuzzer(
                //                                "some name",
                //                                p.first,
                //                                fuzzLocationsAdvancedFuzzer,
                //                                httpFuzzerOptions,
                //                                messageProcessors);
                //                System.out.println("Starting fuzzer");
                //                extension.runFuzzer(httpFuzzerHandler, httpFuzzer);
                //                return new ApiResponseElement("fuzzerId",
                // Integer.toString(httpFuzzer.getScanId()));
                JSONObject fuzzLocationsObject =
                        getJsonObjectFromJsonFilePath(
                                "/home/dennis/zaproxy-proj/zap-extensions/sample_fuzz_locations.json");
                createFuzzLocationsFromJsonInput(fuzzLocationsObject);

                return ApiResponseElement.OK;
            case ACTION_SIMPLE_HTTP_FUZZER:
                TableHistory tableHistory = Model.getSingleton().getDb().getTableHistory();
                RecordHistory recordHistory =
                        getRecordHistory(tableHistory, getParam(params, PARAM_MESSAGE_ID, -1));

                httpFuzzerHandler = new HttpFuzzerHandler();

                String location = getParam(params, PARAM_LOCATION, "");
                int locationStart = Integer.parseInt(location.split(":")[0]);
                int locationEnd = Integer.parseInt(location.split(":")[1]);

                String payloadPath = getParam(params, PARAM_PAYLOAD, "");

                boolean fuzzHeader = getParam(params, PARAM_FUZZ_HEADER, true);
                HttpMessageLocation.Location httpLocation =
                        fuzzHeader
                                ? HttpMessageLocation.Location.REQUEST_HEADER
                                : HttpMessageLocation.Location.REQUEST_BODY;

                List<PayloadGeneratorMessageLocation<?>> fuzzLocations =
                        createFuzzLocations(httpLocation, locationStart, locationEnd, payloadPath);

                HttpFuzzer httpFuzzerSimple =
                        createFuzzer(
                                "some name",
                                recordHistory.getHttpMessage(),
                                fuzzLocations,
                                getOptions(extension.getDefaultFuzzerOptions()),
                                Collections.emptyList());
                System.out.println("Starting fuzzer");
                extension.runFuzzer(httpFuzzerHandler, httpFuzzerSimple);
                return new ApiResponseElement(
                        "fuzzerId", Integer.toString(httpFuzzerSimple.getScanId()));
            default:
                throw new ApiException(ApiException.Type.BAD_ACTION);
        }
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
            HttpMessageLocation.Location location, int start, int end, String payloadPath) {

        List<String> allLines = new ArrayList<>();
        try {
            allLines = Files.readAllLines(Paths.get(payloadPath));
        } catch (IOException e) {
            e.printStackTrace();
        }

        return createPayloadGeneratorMessageLocationList(location, start, end, allLines);
    }

    private List<PayloadGeneratorMessageLocation<?>> createPayloadGeneratorMessageLocationList(
            HttpMessageLocation.Location location, int start, int end, List<String> payloads) {
        TextHttpMessageLocation messageLocation =
                createTextHttpMessageLocationObject(start, end, location);
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

    private TextHttpMessageLocation createTextHttpMessageLocationObject(
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
                new TreeSet<>(fuzzLocations);
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

    private HttpFuzzerOptions getOptions(FuzzerOptions baseOptions) {
        return new HttpFuzzerOptions(baseOptions, false, false, 100, false);
    }

    private Pair<HttpMessage, List<TextHttpMessageLocation>>
            generateHttpMessageLocationsFromHttpMessageJsonInput(String jsonPath)
                    throws IllegalFormatException {
        List<TextHttpMessageLocation> textHttpMessageLocationList = new ArrayList<>();
        JSONObject jsonObject = getJsonObjectFromJsonFilePath(jsonPath);
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
                    createTextHttpMessageLocationObject(
                            headerFuzzLocations.get(i),
                            headerFuzzLocations.get(i + 1),
                            TextHttpMessageLocation.Location.REQUEST_HEADER));
        }
        for (int i = 0; i < bodyFuzzLocations.size(); i += 2) {
            textHttpMessageLocationList.add(
                    createTextHttpMessageLocationObject(
                            bodyFuzzLocations.get(i),
                            bodyFuzzLocations.get(i + 1),
                            TextHttpMessageLocation.Location.REQUEST_BODY));
        }
        HttpMessage httpMessage = createHttpMessageFromJsonMessageObject(messageObject);
        return new Pair<>(httpMessage, textHttpMessageLocationList);
    }

    private JSONObject getJsonObjectFromJsonFilePath(String jsonPath) {
        File initialFile = new File(jsonPath);
        InputStream is = null;
        try {
            is = new FileInputStream(initialFile);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        String jsonTxt = null;
        try {
            assert is != null;
            jsonTxt = IOUtils.toString(is);
        } catch (IOException e) {
            e.printStackTrace();
        }

        return (JSONObject) JSONSerializer.toJSON(jsonTxt);
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

    private List<PayloadGeneratorMessageLocation<?>> createFuzzLocationsFromJsonInput(
            JSONObject fuzzLocationsObject) {
        List<PayloadGeneratorMessageLocation<?>> payloadGeneratorMessageLocationList =
                new ArrayList<>();
        JSONArray fuzzLocationsJsonArray = fuzzLocationsObject.getJSONArray("fuzzLocations");
        for (int i = 0; i < fuzzLocationsJsonArray.size(); i++) {
            JSONObject fuzzLocationObject = fuzzLocationsJsonArray.getJSONObject(i);
            TextHttpMessageLocation.Location location =
                    fuzzLocationObject.get("location").equals("body")
                            ? HttpMessageLocation.Location.REQUEST_BODY
                            : HttpMessageLocation.Location.REQUEST_HEADER;
            int start = fuzzLocationObject.getInt("start");
            int end = fuzzLocationObject.getInt("end");
            JSONArray payloadsArray = fuzzLocationObject.getJSONArray("payloads");
            // Current payloads can be of 3 types
            for (int j = 0; j < payloadsArray.size(); j++) {
                JSONObject payloadObject = payloadsArray.getJSONObject(j);
                String type = payloadObject.get("type").toString();
                if ("file".equals(type)) {
                    payloadGeneratorMessageLocationList.addAll(
                            createFuzzLocations(
                                    location, start, end, payloadObject.getString("path")));
                } else if ("strings".equals(type)) {
                    JSONArray stringContents = payloadObject.getJSONArray("contents");
                    List<String> payloads = new ArrayList<>();
                    for (int k = 0; k < stringContents.size(); k++) {
                        payloads.add(stringContents.getString(k));
                    }
                    payloadGeneratorMessageLocationList.addAll(
                            createPayloadGeneratorMessageLocationList(
                                    location, start, end, payloads));
                } else if ("file fuzzer".equals(type)) {
                    String fileFuzzerLocation = payloadObject.get("location").toString();
                    String[] fileFuzzerLocationSplit = fileFuzzerLocation.split("/");
                    if (fileFuzzerLocationSplit.length == 0) {
                        throw new IllegalStateException(
                                "Invalid Json Input Inbuilt File Fuzzer type doesn't exist: "
                                        + fileFuzzerLocation);
                    }
                    if (fileFuzzerLocationSplit[0].equals("Custom fuzzers")) {
                        payloadGeneratorMessageLocationList.addAll(
                                createFuzzLocations(
                                        location,
                                        start,
                                        end,
                                        Constant.getZapHome()
                                                + "fuzzers/"
                                                + fileFuzzerLocationSplit[1]));
                    } else if (fileFuzzerLocationSplit[0].equals("jbrofuzz")) {
                        // TODO Add jbro fuzz options
                    } else {
                        payloadGeneratorMessageLocationList.addAll(
                                createFuzzLocations(
                                        location,
                                        start,
                                        end,
                                        Constant.getZapHome() + "fuzzers/" + fileFuzzerLocation));
                    }
                } else {
                    throw new IllegalStateException(
                            "Invalid Json Input payload type doesn't exist: "
                                    + payloadObject.get("type"));
                }
            }
        }
        return payloadGeneratorMessageLocationList;
    }
}
