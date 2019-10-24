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

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import net.sf.json.JSONObject;
import org.apache.log4j.Logger;
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
import org.zaproxy.zap.extension.api.ApiResponseElement;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.*;
import org.zaproxy.zap.extension.fuzz.messagelocations.*;
import org.zaproxy.zap.extension.fuzz.payloads.DefaultPayload;
import org.zaproxy.zap.extension.fuzz.payloads.PayloadGeneratorMessageLocation;
import org.zaproxy.zap.extension.fuzz.payloads.generator.DefaultStringPayloadGenerator;
import org.zaproxy.zap.extension.httppanel.Message;
import org.zaproxy.zap.model.HttpMessageLocation;
import org.zaproxy.zap.model.MessageLocation;
import org.zaproxy.zap.model.TextHttpMessageLocation;
import org.zaproxy.zap.utils.ResettableAutoCloseableIterator;

public class FuzzAPI extends ApiImplementor {
    private static final String PREFIX = "fuzz";
    private HttpFuzzerHandler httpFuzzerHandler;
    private ExtensionFuzz extension;

    private static final String ACTION_SIMPLE_HTTP_FUZZER = "simpleHTTPFuzzer";

    private static final Logger LOGGER = Logger.getLogger(FuzzAPI.class);

    public FuzzAPI(ExtensionFuzz ext) {
        this.extension = ext;
        this.addApiAction(new ApiAction(ACTION_SIMPLE_HTTP_FUZZER, new String[] {"id"}));
    }

    @Override
    public String getPrefix() {
        return PREFIX;
    }

    @Override
    public ApiResponse handleApiAction(String name, JSONObject params) throws ApiException {

        switch (name) {
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
                List<HttpFuzzerMessageProcessor> messageProcessors =
                        Collections.<HttpFuzzerMessageProcessor>emptyList();
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
            for (String line : allLines) {
                System.out.println(line);
            }
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
}
