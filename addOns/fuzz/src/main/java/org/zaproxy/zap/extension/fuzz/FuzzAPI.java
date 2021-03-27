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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.TimeUnit;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import net.sf.json.JSONSerializer;
import org.apache.commons.io.IOUtils;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.db.RecordHistory;
import org.parosproxy.paros.db.TableHistory;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.api.ApiAction;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.extension.api.ApiImplementor;
import org.zaproxy.zap.extension.api.ApiResponse;
import org.zaproxy.zap.extension.api.ApiResponseConversionUtils;
import org.zaproxy.zap.extension.api.ApiResponseElement;
import org.zaproxy.zap.extension.api.ApiResponseList;
import org.zaproxy.zap.extension.api.ApiResponseSet;
import org.zaproxy.zap.extension.api.ApiView;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.HttpFuzzer;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.HttpFuzzerHandler;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.HttpFuzzerMessageProcessor;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.HttpFuzzerOptions;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.processors.FuzzerHttpMessageScriptProcessorAdapter;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.processors.HttpFuzzerReflectionDetector;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.processors.RequestContentLengthUpdaterProcessor;
import org.zaproxy.zap.extension.fuzz.messagelocations.MessageLocationsReplacementStrategy;
import org.zaproxy.zap.extension.fuzz.payloads.DefaultPayload;
import org.zaproxy.zap.extension.fuzz.payloads.PayloadGeneratorMessageLocation;
import org.zaproxy.zap.extension.fuzz.payloads.generator.DefaultStringPayloadGenerator;
import org.zaproxy.zap.extension.fuzz.payloads.generator.FileStringPayloadGenerator;
import org.zaproxy.zap.extension.fuzz.payloads.generator.PayloadGenerator;
import org.zaproxy.zap.extension.fuzz.payloads.generator.StringPayloadGenerator;
import org.zaproxy.zap.extension.httppanel.Message;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.model.HttpMessageLocation;
import org.zaproxy.zap.model.MessageLocation;
import org.zaproxy.zap.model.TextHttpMessageLocation;
import org.zaproxy.zap.utils.ResettableAutoCloseableIterator;
import org.zaproxy.zap.view.table.DefaultHistoryReferencesTableEntry;

/**
 *
 *
 * <h1>FuzzAPI ApiImplementation for Fuzz</h1>
 *
 * <p>The FuzzAPI class implements the ApiImplementor to be used as an API gateway for fuzz, it
 * contains methods to get inputs from the users to run the fuzzer, check status, change options or
 * processors, and to get results.
 *
 * <p>The main fuzzer multiplePayloadFuzzer takes in a JSONObject which is specified according to
 * the JSON schema in zap-api-docs.
 *
 * <p>SimpleHttpFuzzer takes few simple arguments and starts the fuzz at 1 particular location.
 *
 * @author Dennis Goyal
 * @author Marius Haberstock
 * @since 2019-11-21
 */
public class FuzzAPI extends ApiImplementor {
    private static final String PREFIX = "fuzz";
    private static final String MESSAGE_LOCATION_HEADER = "header";
    private static final String MESSAGE_LOCATION_BODY = "body";
    private static final String FUZZ_LOCATION_SEPARATOR = ":";
    private static final String PARAM_MESSAGES_SENT = "messagesSent";
    private static final String PARAM_RESULTS = "results";
    private static final String PARAM_MESSAGE_PROCESSORS = "messageProcessors";

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
    private static final String PARAM_SCRIPT_NAME = "scriptName";
    private static final String PARAM_SCRIPT_PARAMS = "scriptParameters";
    private static final String PARAM_SCRIPT_INSERT = "insertAt";
    private static final Logger LOGGER = Logger.getLogger(FuzzAPI.class);

    private FuzzerOptions fuzzerOptions;
    private List<HttpFuzzerMessageProcessor> httpFuzzerMessageProcessors;
    private static final String ACTION_SIMPLE_HTTP_FUZZER = "simpleHttpFuzzer";
    private static final String ACTION_SET_HTTP_FUZZ_OPTIONS = "setHttpFuzzerOptions";
    private static final String ACTION_RESET_DEFAULT_HTTP_FUZZ_OPTIONS =
            "resetHttpFuzzOptionsToDefault";
    private static final String ACTION_ADD_HTTP_FUZZ_MESSAGE_PROCESSOR = "addMessageProcessor";
    private static final String ACTION_REMOVE_HTTP_FUZZ_MESSAGE_PROCESSOR =
            "removeMessageProcessor";
    private static final String ACTION_RESET_DEFAULT_HTTP_FUZZ_MESSAGE_PROCESSORS =
            "resetMessageProcessorsToDefault";
    private static final String VIEW_GET_HTTP_FUZZ_MESSAGE_PROCESSORS = "getMessageProcessors";
    private static final String ACTION_MULTIPLE_PAYLOAD_FUZZER = "multiplePayloadFuzzer";
    private static final String VIEW_FUZZER_PROGRESS = "fuzzerProgress";
    private static final String VIEW_GET_MESSAGES_SENT = "getMessagesSentCount";
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

    public FuzzAPI(ExtensionFuzz ext) {
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
        this.addApiAction(
                new ApiAction(
                        ACTION_ADD_HTTP_FUZZ_MESSAGE_PROCESSOR,
                        new String[] {
                            PARAM_SCRIPT_NAME, PARAM_SCRIPT_PARAMS, PARAM_SCRIPT_INSERT
                        }));
        this.addApiAction(
                new ApiAction(
                        ACTION_REMOVE_HTTP_FUZZ_MESSAGE_PROCESSOR,
                        new String[] {PARAM_SCRIPT_NAME}));
        this.addApiAction(new ApiAction(ACTION_RESET_DEFAULT_HTTP_FUZZ_MESSAGE_PROCESSORS));

        this.addApiView(new ApiView(VIEW_GET_HTTP_FUZZ_MESSAGE_PROCESSORS));
        this.addApiView(new ApiView(VIEW_FUZZER_PROGRESS, new String[] {PARAM_FUZZER_ID}));
        this.addApiView(new ApiView(VIEW_GET_RESULTS, new String[] {PARAM_FUZZER_ID}));
        this.addApiView(new ApiView(VIEW_GET_MESSAGES_SENT, new String[] {PARAM_FUZZER_ID}));
        this.addApiView(new ApiView(VIEW_GET_ALL_SENT_MESSAGES, new String[] {PARAM_FUZZER_ID}));
    }

    @Override
    public String getPrefix() {
        return PREFIX;
    }

    private void resetHttpFuzzerOptions() {
        fuzzerOptions = new FuzzerOptions(getOptions(extension.getDefaultFuzzerOptions()));
    }

    private void resetMessageProcessors() {
        httpFuzzerMessageProcessors = new ArrayList<HttpFuzzerMessageProcessor>();
        httpFuzzerMessageProcessors.add(new RequestContentLengthUpdaterProcessor());
        httpFuzzerMessageProcessors.add(new HttpFuzzerReflectionDetector());
    }

    @Override
    public ApiResponse handleApiView(String name, JSONObject params) throws ApiException {
        HttpFuzzer fuzzer;
        ApiResponseList apiResponseList;
        switch (name) {
            case VIEW_GET_MESSAGES_SENT:
                fuzzer = getFuzzer(params);
                return new ApiResponseElement(
                        PARAM_MESSAGES_SENT, String.valueOf(fuzzer.getMessagesSentCount()));
            case VIEW_FUZZER_PROGRESS:
                fuzzer = getFuzzer(params);
                return new ApiResponseElement(
                        VIEW_FUZZER_PROGRESS, String.valueOf(fuzzer.getProgress()));
            case VIEW_GET_RESULTS:
                fuzzer = getFuzzer(params);
                apiResponseList = new ApiResponseList((PARAM_RESULTS));
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
            case VIEW_GET_ALL_SENT_MESSAGES:
                fuzzer = getFuzzer(params);
                apiResponseList = new ApiResponseList(PARAM_MESSAGES_SENT);

                for (int i = 0; i < fuzzer.getMessagesModel().getRowCount(); i++) {
                    HttpMessage httpMessage;
                    try {
                        httpMessage =
                                ((DefaultHistoryReferencesTableEntry)
                                                fuzzer.getMessagesModel().getEntry(i))
                                        .getHistoryReference()
                                        .getHttpMessage();
                    } catch (HttpMalformedHeaderException | DatabaseException e) {
                        LOGGER.error("Bad HttpMessage", e);
                        throw new ApiException(
                                ApiException.Type.INTERNAL_ERROR,
                                "httpMessage readError doesn't exist",
                                e);
                    }
                    assert httpMessage != null; // This can't be null because its an internal object
                    apiResponseList.addItem(
                            ApiResponseConversionUtils.httpMessageToSet(
                                    httpMessage.getHistoryRef().getHistoryId(), httpMessage));
                }
                return apiResponseList;
            case VIEW_GET_HTTP_FUZZ_MESSAGE_PROCESSORS:
                List<HttpFuzzerMessageProcessor> processors = getMessageProcessors();
                apiResponseList = new ApiResponseList(PARAM_MESSAGE_PROCESSORS);

                for (int i = 0; i < processors.size(); i++) {
                    HttpFuzzerMessageProcessor current = processors.get(i);
                    HashMap<String, String> values = new HashMap<String, String>();
                    values.put("name", current.getName());
                    values.put("class", current.getClass().getCanonicalName());
                    apiResponseList.addItem(
                            new ApiResponseSet<String>(Integer.toString(i), values));
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
    private HttpFuzzer getFuzzer(JSONObject params) throws ApiException {
        int fuzzerId = getParam(params, PARAM_FUZZER_ID, -1);
        List<HttpFuzzer> fuzzersList = extension.getFuzzers(HttpFuzzer.class);
        HttpFuzzer fuzzer = null;
        for (HttpFuzzer f : fuzzersList) {
            if (f.getScanId() == fuzzerId) {
                fuzzer = f;
                break;
            }
        }
        if (fuzzer == null) {
            LOGGER.error("Fuzzer: " + fuzzerId + "doesn't exists.");
            throw new ApiException(ApiException.Type.DOES_NOT_EXIST, "fuzzerId: " + fuzzerId);
        }
        return fuzzer;
    }

    @Override
    public ApiResponse handleApiAction(String name, JSONObject params) throws ApiException {
        HttpFuzzer httpFuzzer;
        HttpFuzzerHandler httpFuzzerHandler;
        switch (name) {
            case ACTION_MULTIPLE_PAYLOAD_FUZZER: // This one needs a valid JSON schema input to work
                LOGGER.info("Starting fuzzer");
                JSONObject fuzzLocationsObject =
                        getJsonObjectFromJsonFilePath(getParam(params, PARAM_JSON_LOCATION, null));
                if (fuzzLocationsObject == null) {
                    LOGGER.error(
                            "Couldn't create net.sf.JSONObject from: "
                                    + getParam(params, PARAM_JSON_LOCATION, ""));
                    throw new ApiException(ApiException.Type.BAD_SCRIPT_FORMAT);
                }
                List<PayloadGeneratorMessageLocation<?>> fuzzLocationsTest =
                        createFuzzLocationsFromJsonInput(fuzzLocationsObject);
                RecordHistory recordHistoryTest = getRecordHistory(params);
                httpFuzzerHandler = new HttpFuzzerHandler();
                HttpFuzzer httpFuzzerTest =
                        httpFuzzerHandler.createFuzzer(
                                recordHistoryTest.getHttpMessage(),
                                fuzzLocationsTest,
                                getOptions(),
                                getMessageProcessors());
                LOGGER.info("Running multiple payload fuzzer.");
                LOGGER.info(
                        "Fuzzer options used are: "
                                + getOptions().getThreadCount()
                                + " "
                                + getOptions().getMaximumRedirects()
                                + " "
                                + getOptions().getMaxErrorsAllowed()
                                + " "
                                + getOptions().getSendMessageDelay()
                                + " "
                                + getOptions().getPayloadsReplacementStrategy());
                LOGGER.info("Message processors: " + listMessageProcessors());
                LOGGER.info("Number of fuzzLocations: " + fuzzLocationsTest.size());
                // creating a new fuzzer handler for every new fuzzer request
                extension.runFuzzer(httpFuzzerHandler, httpFuzzerTest);
                assert httpFuzzerTest
                        != null; // It can't be null if it is null, an exception is thrown before
                return new ApiResponseElement(
                        PARAM_FUZZER_ID, Integer.toString(httpFuzzerTest.getScanId()));
            case ACTION_SIMPLE_HTTP_FUZZER:
                LOGGER.info("Starting fuzzer");
                RecordHistory recordHistory = getRecordHistory(params);
                if (recordHistory.getHttpMessage() == null) {
                    LOGGER.debug("HttpMessage not found in history.");
                    throw new ApiException(
                            ApiException.Type.DOES_NOT_EXIST, "HttpMessage not in scope.");
                }
                httpFuzzerHandler = new HttpFuzzerHandler();

                // Locations are separated by : for e.g. 8:12 (location is the character locations)
                int locationStart = getMessageLocationFromParam(params)[0];
                int locationEnd = getMessageLocationFromParam(params)[1];

                String payloadPath = getParam(params, PARAM_PAYLOAD_PATH, "");

                String requestLocation = getParam(params, PARAM_FUZZ_REQUEST_LOCATION, "");
                HttpMessageLocation.Location httpLocation;
                if (requestLocation.toLowerCase().equals(MESSAGE_LOCATION_BODY)) {
                    httpLocation = HttpMessageLocation.Location.REQUEST_BODY;
                } else if (requestLocation.toLowerCase().equals(MESSAGE_LOCATION_HEADER)) {
                    httpLocation = HttpMessageLocation.Location.REQUEST_HEADER;
                } else {
                    LOGGER.error(
                            "Bad request type, only header or body allowed: " + requestLocation);
                    throw new ApiException(
                            ApiException.Type.BAD_FORMAT,
                            "Invalid request Location: "
                                    + requestLocation
                                    + " only \"body\" or \"header\" allowed");
                }
                List<PayloadGeneratorMessageLocation<?>> fuzzLocations =
                        createFuzzLocations(httpLocation, locationStart, locationEnd, payloadPath);
                HttpFuzzer httpFuzzerSimple =
                        httpFuzzerHandler.createFuzzer(
                                recordHistory.getHttpMessage(),
                                fuzzLocations,
                                getOptions(),
                                getMessageProcessors());
                extension.runFuzzer(httpFuzzerHandler, httpFuzzerSimple);
                assert httpFuzzerSimple
                        != null; // Can't be null if it is an exception should be thrown before
                return new ApiResponseElement(
                        PARAM_FUZZER_ID, Integer.toString(httpFuzzerSimple.getScanId()));
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
            case ACTION_RESET_DEFAULT_HTTP_FUZZ_MESSAGE_PROCESSORS:
                resetMessageProcessors();
                return ApiResponseElement.OK;
            case ACTION_ADD_HTTP_FUZZ_MESSAGE_PROCESSOR:
                addMessageProcessorScript(
                        getParam(params, PARAM_SCRIPT_NAME, null),
                        getParam(params, PARAM_SCRIPT_PARAMS, null),
                        getParam(params, PARAM_SCRIPT_INSERT, -1));
                return ApiResponseElement.OK;
            case ACTION_REMOVE_HTTP_FUZZ_MESSAGE_PROCESSOR:
                removeMessageProcessorScript(getParam(params, PARAM_SCRIPT_NAME, null));
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
     * This method splits the string fuzzLocation for e.g. 8:12 into an ArrayList
     *
     * @param params - This is the JSONObject containing all the params
     * @return - returns an ArrayList for e.g. [8, 12]
     */
    private Integer[] getMessageLocationFromParam(JSONObject params) throws ApiException {
        String fuzzLocation = getParam(params, PARAM_FUZZ_LOCATION, "");
        int locationStart;
        int locationEnd;
        try {
            locationStart = Integer.parseInt(fuzzLocation.split(FUZZ_LOCATION_SEPARATOR)[0]);
            locationEnd = Integer.parseInt(fuzzLocation.split(FUZZ_LOCATION_SEPARATOR)[1]);
        } catch (IllegalArgumentException e) {
            LOGGER.error("Couldn't create integer start and end from: " + fuzzLocation, e);
            throw new ApiException(ApiException.Type.BAD_FORMAT, e);
        }
        if (locationStart > locationEnd) locationStart = locationEnd = 0;
        return (new Integer[] {locationStart, locationEnd});
    }

    private RecordHistory getRecordHistory(JSONObject params) throws ApiException {
        TableHistory tableHistory = Model.getSingleton().getDb().getTableHistory();
        return getRecordHistory(tableHistory, getParam(params, PARAM_MESSAGE_ID, -1));
    }

    /**
     * This method is not supposed to change the default fuzzer options just to keep a track of what
     * was setup by the user so that when creating a fuzzer these fuzz options can be sent over to
     * the fuzzer.
     *
     * @param maxErrorsAllowed - Maximum errors allowed by the fuzzer
     * @param strategy - Strategy to be used Depth first or breadth first
     * @param retriesIOError - Retries on IO error if a message is unable to sent
     * @param delayInMs - delay after a request is sent in Ms
     * @param threads - number of threads running parallel
     */
    private void setHttpFuzzerOptions(
            int maxErrorsAllowed, String strategy, int retriesIOError, int delayInMs, int threads) {
        int tmpMaxErrorsAllowed =
                -1 == maxErrorsAllowed ? fuzzerOptions.getMaxErrorsAllowed() : maxErrorsAllowed;
        int tmpRetriesIOError =
                -1 == retriesIOError ? fuzzerOptions.getRetriesOnIOError() : retriesIOError;
        int tmpDelayInMs = -1 == delayInMs ? (int) fuzzerOptions.getSendMessageDelay() : delayInMs;
        int tmpThreads = -1 == threads ? fuzzerOptions.getThreadCount() : threads;
        MessageLocationsReplacementStrategy messageLocationsReplacementStrategy =
                MessageLocationsReplacementStrategy.DEPTH_FIRST;
        if (strategy.toLowerCase()
                .equals(
                        Constant.messages
                                .getString(
                                        "fuzz.options.label.payloadReplacementStrategy.breadthFirst")
                                .toLowerCase())) {
            messageLocationsReplacementStrategy = MessageLocationsReplacementStrategy.BREADTH_FIRST;
        }
        LOGGER.info(
                "Setting fuzzer options to: "
                        + tmpThreads
                        + " "
                        + tmpRetriesIOError
                        + " "
                        + tmpMaxErrorsAllowed
                        + " "
                        + tmpDelayInMs
                        + " "
                        + messageLocationsReplacementStrategy);
        fuzzerOptions =
                new FuzzerOptions(
                        tmpThreads,
                        tmpRetriesIOError,
                        tmpMaxErrorsAllowed,
                        tmpDelayInMs,
                        TimeUnit.MILLISECONDS,
                        messageLocationsReplacementStrategy);
    }

    /**
     * This method is not supposed to change the default message processors; it just tracks what is
     * set up by the user so new fuzzers can be created with this list of processors.
     *
     * @param scriptName - Name of processor script to attach to fuzzer
     * @param scriptParameters - JSON-formatted Map of parameters passed to this script
     * @param insertAt - Insert processor where? (0=first, 1=second, ... -1=end)
     */
    private void addMessageProcessorScript(
            String scriptName, String scriptParameters, int insertAt) {
        if (httpFuzzerMessageProcessors == null) {
            resetMessageProcessors();
        }
        int where = -1 == insertAt ? httpFuzzerMessageProcessors.size() : insertAt;

        // We claim we're adding a script, but actually we're adding a generic
        // processor that will call the script.
        LOGGER.info(
                "Inserting fuzz message processor script: "
                        + Integer.toString(where)
                        + " "
                        + scriptName);

        // Look up the previously-loaded script
        ScriptWrapper fuzzScriptWrapper =
                Control.getSingleton()
                        .getExtensionLoader()
                        .getExtension(ExtensionScript.class)
                        .getScript(scriptName);

        // We need to convert JSON string to a map
        HashMap<String, String> scriptParameterMap =
                (HashMap<String, String>)
                        JSONObject.toBean(JSONObject.fromObject(scriptParameters), HashMap.class);

        // Create adapter processor using wrapper and parameters
        HttpFuzzerMessageProcessor fuzzScriptAdapter =
                new FuzzerHttpMessageScriptProcessorAdapter(fuzzScriptWrapper, scriptParameterMap);
        httpFuzzerMessageProcessors.add(where, fuzzScriptAdapter);
    }

    /**
     * This method is not supposed to change the default message processors; it just tracks what is
     * set up by the user so new fuzzers can be created with this list of processors.
     *
     * @param scriptName - Name of processor script to remove from list
     */
    private void removeMessageProcessorScript(String scriptName) {
        if (httpFuzzerMessageProcessors == null) {
            resetMessageProcessors();
        }

        // Remove (only) the first processor with a matching name
        for (int i = 0; i < httpFuzzerMessageProcessors.size(); i++) {
            if (scriptName.equals(httpFuzzerMessageProcessors.get(i).getName())) {
                LOGGER.info("Removing fuzz message processor script #" + Integer.toString(i));
                httpFuzzerMessageProcessors.remove(i);
                break;
            }
        }
    }

    private RecordHistory getRecordHistory(TableHistory tableHistory, Integer id)
            throws ApiException {
        RecordHistory recordHistory;
        try {
            recordHistory = tableHistory.read(id);
        } catch (HttpMalformedHeaderException | DatabaseException e) {
            LOGGER.debug("Invalid http Message or Data error", e);
            throw new ApiException(
                    ApiException.Type.INTERNAL_ERROR, "Invalid http Message or Data error", e);
        }
        if (recordHistory == null) {
            LOGGER.debug("Message " + id + " doesn't exist in History.");
            throw new ApiException(ApiException.Type.DOES_NOT_EXIST, Integer.toString(id));
        }
        return recordHistory;
    }

    private List<PayloadGeneratorMessageLocation<?>> createFuzzLocations(
            HttpMessageLocation.Location location, int start, int end, String payloadPath)
            throws ApiException {

        List<String> allLines;
        try {
            allLines = Files.readAllLines(Paths.get(payloadPath));
        } catch (IOException e) {
            LOGGER.error("Couldn't read the input file: " + payloadPath, e);
            throw new ApiException(ApiException.Type.DOES_NOT_EXIST, payloadPath, e);
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

    private HttpFuzzerOptions getOptions() {
        if (fuzzerOptions == null) {
            resetHttpFuzzerOptions();
        }
        return new HttpFuzzerOptions(fuzzerOptions, false, false, 100, false);
    }

    private HttpFuzzerOptions getOptions(FuzzerOptions baseOptions) {
        return new HttpFuzzerOptions(baseOptions, false, false, 100, false);
    }

    private List<HttpFuzzerMessageProcessor> getMessageProcessors() {
        if (httpFuzzerMessageProcessors == null) {
            resetMessageProcessors();
        }
        return new ArrayList<HttpFuzzerMessageProcessor>(httpFuzzerMessageProcessors);
    }

    private String listMessageProcessors() {
        if (httpFuzzerMessageProcessors == null) {
            resetMessageProcessors();
        }

        String result = "";
        for (int i = 0; i < httpFuzzerMessageProcessors.size(); i++) {
            if (i > 0) {
                result += ", ";
            }
            result += httpFuzzerMessageProcessors.get(i).getName();
        }
        return result;
    }

    /**
     * Tries to create a net.sf.json.JSONObject from the local file path, if found create the object
     * and return back
     *
     * @param jsonPath - this is the local path in the environment which contains a valid net.sf
     *     json object
     * @return JSONObject - this is a net.sf.json.JSONObject
     * @code net.sf.json.JSONObject
     */
    private JSONObject getJsonObjectFromJsonFilePath(String jsonPath) throws ApiException {
        File initialFile = new File(jsonPath);
        InputStream is;
        try {
            is = new FileInputStream(initialFile);
        } catch (FileNotFoundException e) {
            LOGGER.error("File not found: " + jsonPath, e);
            throw new ApiException(ApiException.Type.DOES_NOT_EXIST, e);
        }
        String jsonTxt;
        try {
            jsonTxt = IOUtils.toString(is);
        } catch (IOException e) {
            LOGGER.error("Invalid input stream", e);
            try {
                is.close();
            } catch (IOException ex) {
                LOGGER.error("Unable to close input stream", e);
            }
            throw new ApiException(ApiException.Type.BAD_FORMAT, e);
        }
        try {
            is.close();
        } catch (IOException e) {
            LOGGER.error("Unable to close input stream", e);
            throw new ApiException(ApiException.Type.BAD_FORMAT, e);
        }
        return (JSONObject) JSONSerializer.toJSON(jsonTxt);
    }

    /** Parameters to be used for inputting fuzzLocationJsonInput */
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
     * This methods reads the JSON file which contains the fuzzLocations and the different payloads
     * types and locations it follows a particular schema which can be obtained from the repository
     * at
     *
     * @link <a href="https://github.com/zaproxy/zap-api-docs">API DOCS<a/>
     * @param fuzzLocationsObject This is the JSON object from the file that was uploaded
     * @return List of all the fuzzLocations and their pre-generated payloads
     */
    private List<PayloadGeneratorMessageLocation<?>> createFuzzLocationsFromJsonInput(
            JSONObject fuzzLocationsObject) throws ApiException {
        // Add multiple fuzz locations including their multiple payloads to this list!
        List<PayloadGeneratorMessageLocation<?>> payloadGeneratorMessageLocationList =
                new ArrayList<>();
        // Get the JSON object
        JSONArray fuzzLocationsJsonArray =
                fuzzLocationsObject.getJSONArray(jsonInputFuzzLocationsKey);
        // Look for all the fuzz Locations
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
            // Location found now look for payloads
            // Current payloads can be of 3 types
            for (int j = 0; j < payloadsArray.size(); j++) {
                JSONObject payloadObject = payloadsArray.getJSONObject(j);
                String type = payloadObject.get(jsonInputPayloadTypeKey).toString();
                // If payload is of type File
                if (jsonInputPayloadTypeFileValue.equals(type)) {
                    Path path = Paths.get(payloadObject.getString(jsonInputPayloadPathKey));
                    FileStringPayloadGenerator fileStringPayloadGenerator =
                            new FileStringPayloadGenerator(path);
                    payloadGeneratorList.add(fileStringPayloadGenerator);
                    // If payload is of type Strings
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
                    // If payload is of type File Fuzzer
                } else if (jsonInputPayloadTypeFileFuzzerValue.equals(type)) {
                    String fileFuzzerLocation =
                            payloadObject.get(jsonInputFileFuzzerLocationKey).toString();
                    String[] fileFuzzerLocationSplit = fileFuzzerLocation.split("/");
                    if (fileFuzzerLocationSplit.length == 0) {
                        throw new ApiException(
                                ApiException.Type.BAD_SCRIPT_FORMAT,
                                "Invalid JSON input inbuilt File Fuzzer type doesn't exist: "
                                        + fileFuzzerLocation);
                    } else {
                        List<FuzzerPayloadCategory> fileFuzzerCategories =
                                extension.getFuzzersDir().getCategories();
                        List<FuzzerPayloadSource> fuzzerPayloadSourceList =
                                null; // If there is an error list not initialised
                        for (int k = 0; k < fileFuzzerLocationSplit.length; k++) {
                            // The following is a recursive for loop to get to the final payload
                            // page
                            // Reading the string fileFuzzerPath
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
                                    LOGGER.error(
                                            "Invalid JSON input for file fuzzer doesn't exist.");
                                    throw new ApiException(
                                            ApiException.Type.BAD_SCRIPT_FORMAT,
                                            "Invalid JSON, File Fuzzer type doesn't exist: "
                                                    + fileFuzzerLocation);
                                }
                            }
                        }
                    }
                } else {
                    LOGGER.error(
                            "Invalid JSON input payload type doesn't exist."
                                    + payloadObject.get(jsonInputPayloadTypeKey));
                    throw new ApiException(
                            ApiException.Type.BAD_SCRIPT_FORMAT,
                            "Invalid JSON input payload type doesn't exist: "
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
