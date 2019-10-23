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
import java.util.List;
import java.util.SortedSet;
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
import org.zaproxy.zap.extension.fuzz.httpfuzzer.HttpFuzzer;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.HttpFuzzerHandler;
import org.zaproxy.zap.extension.fuzz.messagelocations.*;
import org.zaproxy.zap.extension.fuzz.payloads.Payload;
import org.zaproxy.zap.extension.httppanel.Message;
import org.zaproxy.zap.model.HttpMessageLocation;
import org.zaproxy.zap.model.MessageLocation;
import org.zaproxy.zap.model.TextHttpMessageLocation;

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

                HttpFuzzerHandler httpFuzzerHandler = new HttpFuzzerHandler();

                createFuzzLocations(
                        recordHistory.getHttpMessage(),
                        HttpMessageLocation.Location.REQUEST_HEADER,
                        26,
                        29,
                        "/home/dennis/zaproxy-proj/temp_payloads.txt");
                //HttpFuzzer httpFuzzer = new HttpFuzzer("Some name", extension.getDefaultFuzzerOptions(), recordHistory.getHttpMessage(), "", "", "");
                //                extension.runFuzzer(httpFuzzerHandler, fuzzer);
                //                extension.getFuzzerStarter();
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

    private List<MessageLocationReplacementGenerator<?, MessageLocationReplacement<?>>> createFuzzLocations(
            HttpMessage httpMessage,
            HttpMessageLocation.Location location,
            int start,
            int end,
            String payloadPath) {
        MessageLocation messageLocation = null;
        TextHttpMessageLocation textHttpMessageLocation =
                createTextHttpMessageLocationObjects(start, end, location);
        List<MessageLocationReplacementGenerator<HttpMessage, MessageLocationReplacement<HttpMessage>>> fuzzLocations;
        try {
            List<String> allLines = Files.readAllLines(Paths.get(payloadPath));
            for (String line : allLines) {

            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    private MessageLocationReplacementGenerator<Payload, MessageLocationReplacement<Payload>> createMessageLocatoin;
    private TextHttpMessageLocation createTextHttpMessageLocationObjects(
            int start, int end, HttpMessageLocation.Location location) {
        TextHttpMessageLocation textHttpMessageLocation =
                new TextHttpMessageLocation() {
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
        return textHttpMessageLocation;
    }
}
