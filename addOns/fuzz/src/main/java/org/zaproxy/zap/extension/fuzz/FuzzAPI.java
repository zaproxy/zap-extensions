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
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.TimeUnit;
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
import org.zaproxy.zap.extension.fuzz.httpfuzzer.processors.RequestContentLengthUpdaterProcessor;
import org.zaproxy.zap.extension.fuzz.messagelocations.*;
import org.zaproxy.zap.extension.fuzz.payloads.DefaultPayload;
import org.zaproxy.zap.extension.fuzz.payloads.PayloadGeneratorMessageLocation;
import org.zaproxy.zap.extension.fuzz.payloads.generator.*;
import org.zaproxy.zap.extension.httppanel.Message;
import org.zaproxy.zap.model.HttpMessageLocation;
import org.zaproxy.zap.model.MessageLocation;
import org.zaproxy.zap.model.TextHttpMessageLocation;
import org.zaproxy.zap.utils.Pair;
import org.zaproxy.zap.utils.ResettableAutoCloseableIterator;

/**
 *
 *
 * <h1>FuzzAPI ApiImplementation for Fuzz</h1>
 *
 * <p>The FuzzAPI class implements the ApiImplementor to be used as an API gateway for fuzz, it
 * contains methods to get inputs from the users to run the fuzzer, check status, change options or
 * processors, and to get results.
 *
 * <p>
 *
 * <p>The main fuzzer multiplePayloadFuzzer takes in a JSONObject which is specified according to
 * the json schema in zap-api-docs, the schema is version controlled
 *
 * <p>
 *
 * <p>SimpleHttpFuzzer takes few simple arguments and starts the fuzz at 1 particular location.
 *
 * @author Dennis Goyal <a href=https://github.com/davy320>profile</a> (Feel free to contact me)
 * @author Marius Haberstock
 * @see ExtensionFuzz
 * @see MessageLocationReplacement
 * @see PayloadGenerator
 * @version 1.0
 * @since 2019-11-4
 */
public class FuzzAPI extends ApiImplementor {
    /* Api NAME */
    private static final String PREFIX = "fuzz";
    // TODO to be implemented maybe in a future release
    private static final String SECTION_SIGN = "§";
    // TODO add escape feature to the section sign
    private static final String ESCAPE_CHARACTER = "\\";
    private static final String MESSAGE_LOCATION_HEADER = "header";
    private static final String MESSAGE_LOCATION_BODY = "body";
    private static final String FUZZ_LOCATION_SEPARATOR = ":";

    private ExtensionFuzz extension;

    // Only the parameters that are used for user inputs
    private static final String PARAM_MESSAGE_ID = "messageId";
    private static final String PARAM_PAYLOAD_PATH = "payloadPath";
    private static final String PARAM_FUZZ_LOCATION = "fuzzLocation";
    private static final String PARAM_JSON_LOCATION = "jsonFuzzLocationsFilePath";
    private static final String PARAM_FUZZ_REQUEST_LOCATION = "requestLocation";
    private static final String PARAM_FUZZER_ID = "fuzzerId";
    private static final String PARAM_MAX_ERRORS_ALLOWED = "maxErrors";
    private static final String PARAM_STRATEGY = "strategy";
    private static final String PARAM_RETRIES = "retriesOnIOError";
    private static final String PARAM_DELAY = "delayInMs";
    private static final String PARAM_THREADS = "concurrentScanningThreads";
    // TODO add logs
    private static final Logger LOGGER = Logger.getLogger(FuzzAPI.class);

    /* Default values for Http Fuzzer */
    private HttpFuzzerOptions httpFuzzerOptions;
    /* Default httpFuzzerMessageProcessors if not input by the user */
    private List<HttpFuzzerMessageProcessor> httpFuzzerMessageProcessors;
    private HttpFuzzerHandler httpFuzzerHandler;
    private static final String ACTION_SIMPLE_HTTP_FUZZER = "simpleHttpFuzzer";
    private static final String ACTION_SET_HTTP_FUZZ_OPTIONS = "setHttpFuzzerOptions";
    private static final String ACTION_RESET_DEFAULT_HTTP_FUZZ_OPTIONS =
            "resetHttpFuzzOptionsToDefault";
    private static final String ACTION_MULTIPLE_PAYLOAD_FUZZER = "multiplePayloadFuzzer";
    private static final String VIEW_FUZZER_PROGRESS = "fuzzerProgress";
    private static final String VIEW_GET_MESSAGES_SENT = "getMessagesSentCount";
    // TODO implement this, get a list of all the messages that were sent
    private static final String VIEW_GET_ALL_SENT_MESSAGES = "getAllSentMessages";
    private static final String VIEW_GET_RESULTS = "getResults";
    private static final String ACTION_START_SCAN = "startScan";
    private static final String ACTION_STOP_SCAN = "stopScan";
    private static final String ACTION_PAUSE_SCAN = "pauseScan";
    private static final String ACTION_RESUME_SCAN = "resumeScan";

    /** Provided only for API client generator usage. */
    public FuzzAPI() {
        this(null);
    }

    /* constructor to be used to receive ACTIONS, VIEW requests from the user.*/
    public FuzzAPI(ExtensionFuzz ext) {

        httpFuzzerMessageProcessors = new ArrayList<>();
        this.extension = ext;
        this.addApiAction(
                new ApiAction(
                        ACTION_SIMPLE_HTTP_FUZZER,
                        new String[] {
                            PARAM_MESSAGE_ID,
                            PARAM_FUZZ_REQUEST_LOCATION,
                            PARAM_FUZZ_LOCATION,
                            PARAM_PAYLOAD_PATH
                        }));
        this.addApiAction(
                new ApiAction(
                        ACTION_MULTIPLE_PAYLOAD_FUZZER,
                        new String[] {
                            PARAM_MESSAGE_ID, PARAM_JSON_LOCATION,
                        }));
        this.addApiAction(
                new ApiAction(
                        ACTION_SET_HTTP_FUZZ_OPTIONS,
                        new String[] {},
                        new String[] {
                            PARAM_MAX_ERRORS_ALLOWED,
                            PARAM_STRATEGY,
                            PARAM_RETRIES,
                            PARAM_DELAY,
                            PARAM_THREADS
                        }));
        this.addApiAction(new ApiAction(ACTION_RESET_DEFAULT_HTTP_FUZZ_OPTIONS));
        this.addApiAction(new ApiAction(ACTION_START_SCAN, new String[] {PARAM_FUZZER_ID}));
        this.addApiAction(new ApiAction(ACTION_STOP_SCAN, new String[] {PARAM_FUZZER_ID}));
        this.addApiAction(new ApiAction(ACTION_PAUSE_SCAN, new String[] {PARAM_FUZZER_ID}));
        this.addApiAction(new ApiAction(ACTION_RESUME_SCAN, new String[] {PARAM_FUZZER_ID}));

        this.addApiView(new ApiView(VIEW_FUZZER_PROGRESS, new String[] {PARAM_FUZZER_ID}));
        this.addApiView(new ApiView(VIEW_GET_RESULTS, new String[] {PARAM_FUZZER_ID}));
        this.addApiView(new ApiView(VIEW_GET_MESSAGES_SENT, new String[] {PARAM_FUZZER_ID}));
    }

    @Override
    public String getPrefix() {
        return PREFIX;
    }

    /** resets the api "only" fuzzerOptionsToDefault */
    private void resetHttpFuzzerOptions() {
        httpFuzzerOptions = getOptions(extension.getDefaultFuzzerOptions());
    }

    @Override
    public ApiResponse handleApiView(String name, JSONObject params) throws ApiException {
        HttpFuzzer fuzzer;
        ApiResponse result = null;
        switch (name) {
            case VIEW_GET_MESSAGES_SENT:
                fuzzer = getFuzzer(params);
                if (fuzzer == null) {
                    return new ApiResponseElement(
                            Constant.messages.getString("fuzz.api.response.failure.getfuzzer"));
                }
                return new ApiResponseElement(
                        Constant.messages.getString("fuzz.httpfuzzer.results.toolbar.messagesSent"),
                        String.valueOf(fuzzer.getMessagesSentCount()));
            case VIEW_FUZZER_PROGRESS:
                fuzzer = getFuzzer(params);
                if (fuzzer == null) {
                    return new ApiResponseElement(
                            Constant.messages.getString("fuzz.api.response.failure.getfuzzer"));
                }
                return new ApiResponseElement(
                        Constant.messages.getString("fuzz.toolbar.progress.label"),
                        String.valueOf(fuzzer.getProgress()));
            case VIEW_GET_RESULTS:
                fuzzer = getFuzzer(params);
                if (fuzzer == null) {
                    return new ApiResponseElement(
                            Constant.messages.getString("fuzz.api.response.failure.getfuzzer"));
                }
                ApiResponseList apiResponseList =
                        new ApiResponseList(
                                Constant.messages.getString("fuzz.httpfuzzer.searcher.name"));
                for (int i = 0; i < fuzzer.getMessagesModel().getRowCount(); i++) {
                    HashMap<String, String> hashMap = new HashMap<>();
                    for (int j = 0; j < fuzzer.getMessagesModel().getHeaders().size(); j++) {
                        hashMap.put(
                                fuzzer.getMessagesModel().getHeaders().get(j),
                                fuzzer.getMessagesModel().getValueAt(i, j).toString());
                    }
                    apiResponseList.addItem(new ApiResponseSet<>(Integer.toString(i), hashMap));
                }
                return apiResponseList;
            default:
                throw new ApiException(ApiException.Type.BAD_VIEW);
        }
    }

    /**
     * Retrievs the httpFuzzer only if it exists or has been registered in fuzzers controller.
     *
     * @param params This contains the input params object from the call of handleApi
     * @return fuzzer this returns the HttpFuzzer registered in the FuzzersController with the
     *     specified id.
     */
    private HttpFuzzer getFuzzer(JSONObject params) {
        int fuzzerId = getParam(params, PARAM_FUZZER_ID, -1);
        List<HttpFuzzer> fuzzersList = extension.getFuzzers(HttpFuzzer.class);
        HttpFuzzer fuzzer = null;
        for (HttpFuzzer f : fuzzersList) {
            if (f.getScanId() == fuzzerId) {
                fuzzer = f;
                break;
            }
        }
        return fuzzer;
    }

    @Override
    public ApiResponse handleApiAction(String name, JSONObject params) throws ApiException {
        HttpFuzzer httpFuzzer;
        switch (name) {
            case ACTION_MULTIPLE_PAYLOAD_FUZZER: // This one needs a valid JSON schema input to work
                JSONObject fuzzLocationsObject =
                        getJsonObjectFromJsonFilePath(getParam(params, PARAM_JSON_LOCATION, null));
                List<PayloadGeneratorMessageLocation<?>> fuzzLocationsTest =
                        createFuzzLocationsFromJsonInput(fuzzLocationsObject);

                TableHistory tableHistoryTest = Model.getSingleton().getDb().getTableHistory();
                RecordHistory recordHistoryTest =
                        getRecordHistory(tableHistoryTest, getParam(params, PARAM_MESSAGE_ID, -1));
                List<HttpFuzzerMessageProcessor> processors = new ArrayList<>();
                processors.add(RequestContentLengthUpdaterProcessor.getInstance());
                HttpFuzzer httpFuzzerTest =
                        createFuzzer(
                                recordHistoryTest.getHttpMessage(),
                                fuzzLocationsTest,
                                getOptions(extension.getDefaultFuzzerOptions()),
                                processors);
                // creating a new fuzzer handler for every new fuzzer request
                httpFuzzerHandler = new HttpFuzzerHandler();
                extension.runFuzzer(httpFuzzerHandler, httpFuzzerTest);
                assert httpFuzzerTest != null;
                return new ApiResponseElement(
                        Constant.messages.getString("fuzz.api.response.fuzzerid"),
                        Integer.toString(httpFuzzerTest.getScanId()));
            case ACTION_SIMPLE_HTTP_FUZZER:
                TableHistory tableHistory = Model.getSingleton().getDb().getTableHistory();
                RecordHistory recordHistory =
                        getRecordHistory(tableHistory, getParam(params, PARAM_MESSAGE_ID, -1));

                httpFuzzerHandler = new HttpFuzzerHandler();
                // Locations are separated by : for e.g. 8:12 (location is the character locations)
                String fuzzLocation = getParam(params, PARAM_FUZZ_LOCATION, "");
                int locationStart =
                        Integer.parseInt(fuzzLocation.split(FUZZ_LOCATION_SEPARATOR)[0]);
                int locationEnd = Integer.parseInt(fuzzLocation.split(FUZZ_LOCATION_SEPARATOR)[1]);

                String payloadPath = getParam(params, PARAM_PAYLOAD_PATH, null);

                String fuzzHeader = getParam(params, PARAM_FUZZ_REQUEST_LOCATION, null);
                HttpMessageLocation.Location httpLocation;
                if (fuzzHeader.toLowerCase().equals(MESSAGE_LOCATION_BODY)) {
                    httpLocation = HttpMessageLocation.Location.REQUEST_BODY;
                } else if (fuzzHeader.toLowerCase().equals(MESSAGE_LOCATION_HEADER)) {
                    httpLocation = HttpMessageLocation.Location.REQUEST_HEADER;
                } else {
                    return ApiResponseElement.FAIL;
                }
                List<PayloadGeneratorMessageLocation<?>> fuzzLocations =
                        createFuzzLocations(httpLocation, locationStart, locationEnd, payloadPath);

                httpFuzzerMessageProcessors.add(RequestContentLengthUpdaterProcessor.getInstance());
                HttpFuzzer httpFuzzerSimple =
                        createFuzzer(
                                recordHistory.getHttpMessage(),
                                fuzzLocations,
                                getOptions(extension.getDefaultFuzzerOptions()),
                                httpFuzzerMessageProcessors);
                extension.runFuzzer(httpFuzzerHandler, httpFuzzerSimple);
                assert httpFuzzerSimple != null;
                return new ApiResponseElement(
                        "fuzz.api.response.fuzzerid",
                        Integer.toString(httpFuzzerSimple.getScanId()));
            case ACTION_RESET_DEFAULT_HTTP_FUZZ_OPTIONS:
                resetHttpFuzzerOptions();
                return ApiResponseElement.OK;
            case ACTION_SET_HTTP_FUZZ_OPTIONS:
                setHttpFuzzerOptions(
                        getParam(params, PARAM_MAX_ERRORS_ALLOWED, -1),
                        getParam(params, PARAM_STRATEGY, null),
                        getParam(params, PARAM_RETRIES, -1),
                        getParam(params, PARAM_DELAY, -1),
                        getParam(params, PARAM_THREADS, -1));
                return ApiResponseElement.OK;
            case ACTION_START_SCAN:
                httpFuzzer = getFuzzer(params);
                httpFuzzer.startScan();
                return ApiResponseElement.OK;
            case ACTION_STOP_SCAN:
                httpFuzzer = getFuzzer(params);
                httpFuzzer.stopScan();
                return ApiResponseElement.OK;
            case ACTION_PAUSE_SCAN:
                httpFuzzer = getFuzzer(params);
                httpFuzzer.pauseScan();
                return ApiResponseElement.OK;
            case ACTION_RESUME_SCAN:
                httpFuzzer = getFuzzer(params);
                httpFuzzer.resumeScan();
                return ApiResponseElement.OK;
            default:
                throw new ApiException(ApiException.Type.BAD_ACTION);
        }
    }

    /**
     * This method is not supposed to change the default fuzzer options just to keep a track of what
     * was setup by the user so that when creating a fuzzer these fuzz options can be sent over to
     * the fuzzer
     *
     * @params these params are the same in fuzz options tab
     * @return void sets up the fuzz options in the default object where it is stored
     */
    private void setHttpFuzzerOptions(
            int maxErrorsAllowed, String strategy, int retriesIOError, int delayInMs, int threads) {
        FuzzOptions fuzzOptions = new FuzzOptions();
        if (maxErrorsAllowed != -1) {
            fuzzOptions.setDefaultMaxErrorsAllowed(maxErrorsAllowed);
        }
        if (retriesIOError != -1) {
            fuzzOptions.setDefaultRetriesOnIOError(retriesIOError);
        }
        if (delayInMs != -1) {
            fuzzOptions.setDefaultFuzzDelayInMs(delayInMs);
        }
        if (threads != -1) {
            fuzzOptions.setDefaultThreadsPerFuzzer(threads);
        }
        if (strategy.toLowerCase()
                .equals(
                        Constant.messages
                                .getString(
                                        "fuzz.options.label.payloadReplacementStrategy.depthFirst")
                                .toLowerCase())) {
            fuzzOptions.setDefaultPayloadReplacementStrategy(
                    MessageLocationsReplacementStrategy.DEPTH_FIRST);
        } else if (strategy.toLowerCase()
                .equals(
                        Constant.messages
                                .getString(
                                        "fuzz.options.label.payloadReplacementStrategy.breadthFirst")
                                .toLowerCase())) {
            fuzzOptions.setDefaultPayloadReplacementStrategy(
                    MessageLocationsReplacementStrategy.BREADTH_FIRST);
        }
        httpFuzzerOptions = getOptions(fuzzOptions);
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
        StringPayloadGenerator payloadGenerator;
        payloadGenerator = new DefaultStringPayloadGenerator(payloads);
        return getPayloadGeneratorMessageLocationList(location, start, end, payloadGenerator);
    }

    private List<PayloadGeneratorMessageLocation<?>> getPayloadGeneratorMessageLocationList(
            HttpMessageLocation.Location location,
            int start,
            int end,
            StringPayloadGenerator payloadGenerator) {
        TextHttpMessageLocation messageLocation =
                createTextHttpMessageLocationObject(start, end, location);
        List<PayloadGeneratorMessageLocation<?>> payloadGeneratorMessageLocationList =
                new ArrayList<>();
        ResettableAutoCloseableIterator<DefaultPayload> resettableAutoCloseableIterator =
                payloadGenerator.iterator();
        PayloadGeneratorMessageLocation<?> payloadGeneratorMessageLocation =
                new PayloadGeneratorMessageLocation<>(
                        messageLocation,
                        payloadGenerator.getNumberOfPayloads(),
                        resettableAutoCloseableIterator);
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
                return HttpMessage.class;
            }
            // There is no need for these but can be fixed
            // All of the functions below no need probably
            @Override
            public String getDescription() {
                return (start + FUZZ_LOCATION_SEPARATOR + end);
            }

            @Override
            public String getValue() {
                return (start + FUZZ_LOCATION_SEPARATOR + end);
            }

            @Override
            public boolean overlaps(MessageLocation otherLocation) {
                return (((start + FUZZ_LOCATION_SEPARATOR + end)).equals(otherLocation.getValue()));
            }

            @Override
            public int compareTo(MessageLocation messageLocation) {
                return (messageLocation
                        .getValue()
                        .compareTo(((start + FUZZ_LOCATION_SEPARATOR + end))));
            }
        };
    }

    /**
     * Method copied from HttpFuzzerHandler
     *
     * @see HttpFuzzerHandler /* Used to create the fuzzer
     */
    /* Didn't want to change fuzzerHandler to public so reusing it */
    private HttpFuzzer createFuzzer(
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
                createFuzzerName(message),
                options,
                message,
                (List<MessageLocationReplacementGenerator<?, MessageLocationReplacement<?>>>)
                        (ArrayList) fuzzLocations,
                multipleMessageLocationsReplacer,
                processors);
    }

    /**
     * Method copied from HttpFuzzerHandler
     *
     * @see HttpFuzzerHandler Used to shrink the name of the fuzzer
     */
    private String createFuzzerName(HttpMessage message) {
        String uri = message.getRequestHeader().getURI().toString();
        if (uri.length() > 30) {
            uri = uri.substring(0, 14) + ".." + uri.substring(uri.length() - 15, uri.length());
        }
        return Constant.messages.getString("fuzz.httpfuzzer.fuzzerNamePrefix", uri);
    }

    private HttpFuzzerOptions getOptions(FuzzerOptions baseOptions) {
        return new HttpFuzzerOptions(baseOptions, false, false, 100, false);
    }

    private HttpFuzzerOptions getOptions(FuzzOptions fuzzOptions) {
        FuzzerOptions baseOptions =
                new FuzzerOptions(
                        fuzzOptions.getDefaultThreadsPerFuzzer(),
                        fuzzOptions.getDefaultRetriesOnIOError(),
                        fuzzOptions.getDefaultMaxErrorsAllowed(),
                        fuzzOptions.getDefaultFuzzDelayInMs(),
                        TimeUnit.MILLISECONDS,
                        fuzzOptions.getDefaultPayloadReplacementStrategy());
        return new HttpFuzzerOptions(baseOptions, false, false, 100, false);
    }

    // TODO try and implement this Start using this
    // Testing required
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

    /**
     * Tries to create a net.sf.jsonobject from the local file path If found create the object and
     * return back
     *
     * @param jsonPath this is the local path in the environment which contains a valid net.sf json
     *     object
     * @return net sf Jsonobject
     */
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

    /**
     * This message is not being used right now maybe implementation for a future release //TODO
     *
     * @param messageObject
     * @return
     */
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

    /** Parameters to be used for inputing fuzzLocationJsonInput */
    private static final String jsonInputFuzzLocationsKey = "fuzzLocations";

    private static final String jsonInputFuzzLocationKey = "requestLocation";
    private static final String jsonInputFuzzLocationStartKey = "start";
    private static final String jsonInputFuzzLocationEndKey = "end";
    private static final String jsonInputPayloadsKey = "payloads";
    private static final String jsonInputPayloadTypeKey = "payloadType";
    private static final String jsonInputPayloadPathKey = "filePath";
    private static final String jsonInputPayloadContentsKey = "contents";
    private static final String jsonInputFileFuzzerLocationKey = "fileFuzzerPath";

    private static final String jsonInputPayloadTypeFileValue = "file";
    private static final String jsonInputPayloadTypeFileFuzzerValue = "fileFuzzer";
    private static final String jsonInputPayloadTypeStringsValue = "strings";

    /**
     * This methods reads the Json file which contains the fuzzLocations and the different payloads
     * types and locations
     * It follows a particular schema which can be obtained from the repository at
     * @link <a href="https://github.com/zaproxy/zap-api-docs">API DOCS<a/>
     * @param fuzzLocationsObject This is the json object from the file that was uploaded
     * @return List of all the fuzzLocations and their pre-generated payloads
     * @version 1.0
     */
    private List<PayloadGeneratorMessageLocation<?>> createFuzzLocationsFromJsonInput(
            JSONObject fuzzLocationsObject) {
        //Add multiple fuzz locations including their multiple payloads to this list!
        List<PayloadGeneratorMessageLocation<?>> payloadGeneratorMessageLocationList =
                new ArrayList<>();
        //Get the json object
        JSONArray fuzzLocationsJsonArray =
                fuzzLocationsObject.getJSONArray(jsonInputFuzzLocationsKey);
        //Look for all the fuzz Locations
        for (int i = 0; i < fuzzLocationsJsonArray.size(); i++) {
            List<PayloadGenerator<DefaultPayload>> payloadGeneratorList = new ArrayList<>();
            JSONObject fuzzLocationObject = fuzzLocationsJsonArray.getJSONObject(i);
            TextHttpMessageLocation.Location location =
                    fuzzLocationObject.get(jsonInputFuzzLocationKey).equals(MESSAGE_LOCATION_BODY)
                            ? HttpMessageLocation.Location.REQUEST_BODY
                            : HttpMessageLocation.Location.REQUEST_HEADER;
            int start = fuzzLocationObject.getInt(jsonInputFuzzLocationStartKey);
            int end = fuzzLocationObject.getInt(jsonInputFuzzLocationEndKey);
            JSONArray payloadsArray = fuzzLocationObject.getJSONArray(jsonInputPayloadsKey);
            //Location found now look for payloads
            // Current payloads can be of 3 types
            for (int j = 0; j < payloadsArray.size(); j++) {
                JSONObject payloadObject = payloadsArray.getJSONObject(j);
                String type = payloadObject.get(jsonInputPayloadTypeKey).toString();
                //If payload is of type File
                if (jsonInputPayloadTypeFileValue.equals(type)) {
                    Path path = Paths.get(payloadObject.getString(jsonInputPayloadPathKey));
                    FileStringPayloadGenerator fileStringPayloadGenerator =
                            new FileStringPayloadGenerator(path);
                    payloadGeneratorList.add(fileStringPayloadGenerator);
                //If payload is of type Strings
                } else if (jsonInputPayloadTypeStringsValue.equals(type)) {
                    JSONArray stringContents =
                            payloadObject.getJSONArray(jsonInputPayloadContentsKey);
                    List<String> payloads = new ArrayList<>();
                    for (int k = 0; k < stringContents.size(); k++) {
                        payloads.add(stringContents.getString(k));
                    }
                    DefaultStringPayloadGenerator defaultStringPayloadGenerator =
                            new DefaultStringPayloadGenerator(payloads);
                    payloadGeneratorList.add(defaultStringPayloadGenerator);
                //If payload is of type File Fuzzer
                } else if (jsonInputPayloadTypeFileFuzzerValue.equals(type)) {
                    String fileFuzzerLocation =
                            payloadObject.get(jsonInputFileFuzzerLocationKey).toString();
                    String[] fileFuzzerLocationSplit = fileFuzzerLocation.split("/");
                    if (fileFuzzerLocationSplit.length == 0) {
                        throw new IllegalStateException(
                                "Invalid Json Input Inbuilt File Fuzzer type doesn't exist: "
                                        + fileFuzzerLocation);
                    } else {
                        List<FuzzerPayloadCategory> fileFuzzerCategories =
                                extension.getFuzzersDir().getCategories();
                        List<FuzzerPayloadSource> fuzzerPayloadSourceList =
                                null; // If there is an error list not initialised
                        for (int k = 0; k < fileFuzzerLocationSplit.length; k++) {
                            for (int l = 0; l < fileFuzzerCategories.size(); l++) {
                                if (fileFuzzerCategories
                                                .get(l)
                                                .toString()
                                                .equals(fileFuzzerLocationSplit[k])
                                        && (k < (fileFuzzerLocationSplit.length - 1))) {
                                    if (k == (fileFuzzerLocationSplit.length - 2)) {
                                        fuzzerPayloadSourceList =
                                                fileFuzzerCategories
                                                        .get(l)
                                                        .getFuzzerPayloadSources();
                                        break;
                                    } else {
                                        fileFuzzerCategories =
                                                fileFuzzerCategories.get(l).getSubCategories();
                                    }
                                }
                            }
                            if ((k == fileFuzzerLocationSplit.length - 1)) {
                                if (fuzzerPayloadSourceList != null) {
                                    for (FuzzerPayloadSource fuzzerPayloadSource :
                                            fuzzerPayloadSourceList) {
                                        if (fuzzerPayloadSource
                                                .toString()
                                                .equals(fileFuzzerLocationSplit[k])) {

                                            StringPayloadGenerator payloadGen =
                                                    fuzzerPayloadSource.getPayloadGenerator();
                                            payloadGeneratorList.add(payloadGen);
                                            break;
                                        }
                                    }
                                } else {
                                    throw new IllegalArgumentException(
                                            "Invalid Json File Fuzzer type doesn't exist: ");
                                }
                            }
                        }
                    }
                } else {
                    throw new IllegalStateException(
                            "Invalid Json Input payload type doesn't exist: "
                                    + payloadObject.get(jsonInputPayloadTypeKey));
                }
            }
            FuzzerPayloadGenerator fuzzerPayloadGenerator =
                    new FuzzerPayloadGenerator(payloadGeneratorList);
            payloadGeneratorMessageLocationList.addAll(
                    getPayloadGeneratorMessageLocationList(
                            location, start, end, fuzzerPayloadGenerator));
        }
        return payloadGeneratorMessageLocationList;
    }
}
